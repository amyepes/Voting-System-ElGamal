/* ==========================================================================
   CRYPTOVOTE CLIENT-SIDE CRYPTOGRAPHIC ENGINE
   Pure-JS BigInt modular arithmetic, ElGamal, NIZK and dynamic UI bindings
   ========================================================================== */

// RFC 3526 Group 14 2048-bit MODP Prime Modulus
const HEX_P = 
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
    "FFFFFFFFFFFFFFFF";

const p = BigInt("0x" + HEX_P);
const g = 2n;
const q = (p - 1n) / 2n;

// Global state holding cryptographic params fetched from the server
let serverParams = {
    p: p,
    g: g,
    q: q,
    u: null
};

// Variable holding prepared vote payload
let preparedPayload = null;

// ==========================================
// 1. MODULAR ARITHMETIC UTILITIES
// ==========================================

/**
 * Computes (base^exponent) % modulus using binary modular exponentiation.
 */
function modPow(base, exponent, modulus) {
    if (modulus === 1n) return 0n;
    let result = 1n;
    base = base % modulus;
    let exp = exponent;
    while (exp > 0n) {
        if (exp % 2n === 1n) {
            result = (result * base) % modulus;
        }
        exp = exp / 2n;
        base = (base * base) % modulus;
    }
    return result;
}

/**
 * Computes modular inverse using the Extended Euclidean Algorithm.
 * Since p is prime, modInverse(a, p) returns x such that a*x = 1 mod p.
 */
function modInverse(a, m) {
    let m0 = m;
    let y = 0n, x = 1n;
    if (m === 1n) return 0n;
    let tempA = a;
    while (tempA > 1n) {
        let div = tempA / m;
        let t = m;
        m = tempA % m;
        tempA = t;
        t = y;
        y = x - div * y;
        x = t;
    }
    if (x < 0n) x = x + m0;
    return x;
}

/**
 * Generates a cryptographically secure random BigInt in [1, maxBigInt].
 */
function randomBigInt(maxBigInt) {
    const bitLength = maxBigInt.toString(2).length;
    const byteLength = Math.ceil(bitLength / 8) + 8; // add extra bytes padding to prevent bias
    const bytes = new Uint8Array(byteLength);
    window.crypto.getRandomValues(bytes);
    
    let hex = "0x";
    for (let b of bytes) {
        hex += b.toString(16).padStart(2, '0');
    }
    return (BigInt(hex) % maxBigInt) + 1n;
}

/**
 * Computes SHA-256 hash of the arguments joined together and returns it as an integer modulo q.
 */
async function sha256Hash(...args) {
    const concatenated = args.map(arg => arg.toString()).join("");
    const msgBuffer = new TextEncoder().encode(concatenated);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return BigInt("0x" + hashHex) % q;
}

// ==========================================
// 2. CRYPTOGRAPHIC PROOF GENERATION
// ==========================================

/**
 * Performs client-side ElGamal encryption and generates the 1-out-of-2 Sigma OR NIZK proof.
 * Returns the exact JSON payload structured for API transmission.
 */
async function generateVotePayload(token, voteVal, u) {
    const b = BigInt(voteVal); // 1n for YES, 0n for NO
    const r = randomBigInt(q - 1n); // Random blinding factor in [1, q-1]
    
    // 1. Compute ElGamal Ciphertext
    // c1 = g^r mod p
    // c2 = (u^r * g^b) mod p
    const c1 = modPow(g, r, p);
    const g_b = modPow(g, b, p);
    const c2 = (modPow(u, r, p) * g_b) % p;
    
    // Declarations of proof commitments, challenges, and responses
    let A0, B0, A1, B1;
    let ch0, ch1, s0, s1;
    
    // Blinding randomness for honest branch
    const w = randomBigInt(q - 1n);
    
    const g_inv = modInverse(g, p);
    const c1_inv = modInverse(c1, p);
    const c2_inv = modInverse(c2, p);
    const c2_div_g = (c2 * g_inv) % p;
    const c2_div_g_inv = modInverse(c2_div_g, p);

    if (b === 0n) {
        // ==========================================
        // VOTE IS 0: Real branch is 0, Simulate branch 1
        // ==========================================
        
        // A. Honest Branch 0 commitments
        A0 = modPow(g, w, p);
        B0 = modPow(u, w, p);
        
        // B. Simulated Branch 1 commitments
        ch1 = randomBigInt(q - 1n);
        s1 = randomBigInt(q - 1n);
        
        // A1 = g^s1 * c1^-ch1 mod p
        const g_s1 = modPow(g, s1, p);
        const c1_inv_ch1 = modPow(c1_inv, ch1, p);
        A1 = (g_s1 * c1_inv_ch1) % p;
        
        // B1 = u^s1 * (c2 * g^-1)^-ch1 mod p
        const u_s1 = modPow(u, s1, p);
        const c2_div_g_inv_ch1 = modPow(c2_div_g_inv, ch1, p);
        B1 = (u_s1 * c2_div_g_inv_ch1) % p;
        
        // C. Compute Fiat-Shamir hash challenge
        const ch = await sha256Hash(g, u, c1, c2, A0, B0, A1, B1);
        
        // D. Split challenge
        ch0 = (ch - ch1) % q;
        if (ch0 < 0n) ch0 += q;
        
        // E. Compute honest response
        s0 = (w + ch0 * r) % q;
        
    } else {
        // ==========================================
        // VOTE IS 1: Real branch is 1, Simulate branch 0
        // ==========================================
        
        // A. Simulated Branch 0 commitments
        ch0 = randomBigInt(q - 1n);
        s0 = randomBigInt(q - 1n);
        
        // A0 = g^s0 * c1^-ch0 mod p
        const g_s0 = modPow(g, s0, p);
        const c1_inv_ch0 = modPow(c1_inv, ch0, p);
        A0 = (g_s0 * c1_inv_ch0) % p;
        
        // B0 = u^s0 * c2^-ch0 mod p
        const u_s0 = modPow(u, s0, p);
        const c2_inv_ch0 = modPow(c2_inv, ch0, p);
        B0 = (u_s0 * c2_inv_ch0) % p;
        
        // B. Honest Branch 1 commitments
        A1 = modPow(g, w, p);
        B1 = modPow(u, w, p);
        
        // C. Compute Fiat-Shamir hash challenge
        const ch = await sha256Hash(g, u, c1, c2, A0, B0, A1, B1);
        
        // D. Split challenge
        ch1 = (ch - ch0) % q;
        if (ch1 < 0n) ch1 += q;
        
        // E. Compute honest response
        s1 = (w + ch1 * r) % q;
    }
    
    // Format JSON Payload matching required structure in Section 4 of SKILL.md
    return {
        token: token,
        ciphertext: {
            c1: c1.toString(),
            c2: c2.toString()
        },
        proof: {
            type: "NIZK 0 1 FS",
            challenge: (ch0 + ch1) % q === 0n ? q.toString() : ((ch0 + ch1) % q).toString(), // optional total FS
            challenge_0: ch0.toString(),
            challenge_1: ch1.toString(),
            response_0: s0.toString(),
            response_1: s1.toString(),
            A0: A0.toString(),
            B0: B0.toString(),
            A1: A1.toString(),
            B1: B1.toString()
        },
        // Metadata fields solely for UI live math visualizer panel
        meta: {
            b: b.toString(),
            r: r.toString(),
            ch: ((ch0 + ch1) % q).toString()
        }
    };
}

// ==========================================
// 3. UI RENDERING & CONTROLLER LOGIC
// ==========================================

/**
 * Triggers modal popup showing validation success/errors.
 */
function showModal(title, message, isSuccess) {
    const modal = document.getElementById("status-modal");
    const body = document.getElementById("modal-body");
    
    body.innerHTML = `
        <h3 class="status-modal-title ${isSuccess ? 'success' : 'error'}">
            ${isSuccess ? '✅ Success' : '❌ Error'} - ${title}
        </h3>
        <div class="status-modal-body">${message}</div>
        <button class="btn btn-primary" onclick="closeModal()">Close</button>
    `;
    modal.classList.remove("hidden");
}

function closeModal() {
    document.getElementById("status-modal").classList.add("hidden");
}

/**
 * Renders the live audit ledger logs of the election.
 */
function renderLedger(logs) {
    const feed = document.getElementById("ledger-feed");
    if (!feed) return;
    
    if (!logs || logs.length === 0) {
        feed.innerHTML = `<div class="empty-state">No transaction logs available yet. Cast a vote to see the ledger in action!</div>`;
        return;
    }
    
    // Sort logs descending to show newest first
    const sortedLogs = [...logs].reverse();
    
    feed.innerHTML = sortedLogs.map(log => {
        const isValid = log.status === "VALIDATED";
        return `
            <div class="log-item">
                <div class="log-header">
                    <span class="log-time">${log.timestamp}</span>
                    <span class="log-token">Token: ${log.token}</span>
                    <span class="log-status ${isValid ? 'validated' : 'rejected'}">${log.status}</span>
                </div>
                <div class="log-details">
                    <div class="log-detail-row">
                        <span class="log-detail-label">c₁:</span>
                        <span class="log-detail-val">${log.c1.substring(0, 40)}...</span>
                    </div>
                    <div class="log-detail-row">
                        <span class="log-detail-label">c₂:</span>
                        <span class="log-detail-val">${log.c2.substring(0, 40)}...</span>
                    </div>
                    ${isValid ? `
                    <div class="log-detail-row" style="color: var(--success-color); margin-top: 4px; font-weight: 500;">
                        <span>✓ Verified NIZK equations matching Fiat-Shamir heuristics. Accumulated homomorphically.</span>
                    </div>
                    ` : `
                    <div class="log-detail-row" style="color: var(--danger-color); margin-top: 4px; font-weight: 500;">
                        <span>⚠️ Verification failure. Checked proof commitments and rejected payload.</span>
                    </div>
                    `}
                </div>
            </div>
        `;
    }).join("");
}

/**
 * Fetches general parameter and accumulator state, executing UI refreshes.
 */
async function fetchState() {
    try {
        const res = await fetch("/api/election/state");
        const state = await res.json();
        
        // Update Accumulator Stats
        const votesCount = document.getElementById("val-votes-count");
        if (votesCount) votesCount.textContent = state.total_votes_cast;
        
        const c1Val = document.getElementById("val-c1");
        if (c1Val) c1Val.textContent = state.aggregated_c1;
        
        const c2Val = document.getElementById("val-c2");
        if (c2Val) c2Val.textContent = state.aggregated_c2;
        
        const statusTag = document.getElementById("val-election-status");
        if (statusTag) {
            if (state.is_closed) {
                statusTag.textContent = "ELECTION CLOSED";
                statusTag.className = "election-status-tag closed";
            } else {
                statusTag.textContent = "ELECTION OPEN";
                statusTag.className = "election-status-tag open";
            }
        }
        
        // Render logs in the ledger panel
        renderLedger(state.logs);
        
        // ==========================================
        // ADMIN SPECIFIC RENDERING
        // ==========================================
        
        // 1. Tokens List
        const tokenList = document.getElementById("token-registry-list");
        if (tokenList && state.tokens) {
            const tokens = Object.entries(state.tokens);
            if (tokens.length === 0) {
                tokenList.innerHTML = `<div class="empty-state">No tokens registered yet. Generate some above!</div>`;
            } else {
                tokenList.innerHTML = tokens.reverse().map(([tid, used]) => `
                    <div class="token-row">
                        <span>${tid}</span>
                        <span class="token-status ${used ? 'consumed' : 'unused'}">${used ? 'Consumed' : 'Unused'}</span>
                    </div>
                `).join("");
            }
        }
        
        // 2. Closed Results Decryption details
        if (state.is_closed) {
            const resultsCard = document.getElementById("results-display-card");
            if (resultsCard) {
                // If election is closed and tally not yet showing, trigger close to fetch results
                const lockOverlay = document.getElementById("results-lock-overlay");
                const activeContent = document.getElementById("results-active-content");
                
                if (lockOverlay && !lockOverlay.classList.contains("hidden")) {
                    // Call close API to get decrypted counts
                    await triggerCloseTallySilent();
                }
            }
        }
        
    } catch (err) {
        console.error("Error polling state:", err);
    }
}

/**
 * Triggers admin close silently to retrieve decrypted tally (used during polling checks).
 */
async function triggerCloseTallySilent() {
    try {
        const res = await fetch("/api/election/close", { method: "POST" });
        if (res.ok) {
            const data = await res.json();
            renderResults(data);
        }
    } catch (e) {}
}

/**
 * Render decrypted tally results with visual percentage bars.
 */
function renderResults(data) {
    const lockOverlay = document.getElementById("results-lock-overlay");
    const activeContent = document.getElementById("results-active-content");
    
    if (lockOverlay) lockOverlay.classList.add("hidden");
    if (activeContent) activeContent.classList.remove("hidden");
    
    const yesCount = document.getElementById("val-yes-count");
    if (yesCount) yesCount.textContent = data.yes_tally;
    
    const noCount = document.getElementById("val-no-count");
    if (noCount) noCount.textContent = data.no_tally;
    
    const total = data.total_votes_cast;
    const yesPct = total > 0 ? Math.round((data.yes_tally / total) * 100) : 0;
    const noPct = total > 0 ? 100 - yesPct : 0;
    
    const yesBar = document.getElementById("val-yes-percentage-bar");
    if (yesBar) yesBar.style.width = `${yesPct}%`;
    
    const labelYes = document.getElementById("val-yes-percentage");
    if (labelYes) labelYes.textContent = `${yesPct}% YES`;
    
    const labelNo = document.getElementById("val-no-percentage");
    if (labelNo) labelNo.textContent = `${noPct}% NO`;
    
    // Decryption math
    const valDecC2 = document.getElementById("val-dec-c2");
    if (valDecC2) valDecC2.textContent = data.accumulator.c2;
    
    const valDecTarget = document.getElementById("val-dec-target");
    if (valDecTarget) {
        // Estimate of target by evaluating C2 * C1^-alpha mod p
        valDecTarget.textContent = "Solved Decrypted Tally Value (g^σ mod p)";
    }
    
    const valDecSolved = document.getElementById("val-dec-solved");
    if (valDecSolved) valDecSolved.textContent = data.yes_tally;
}

// ==========================================
// 4. ACTION HANDLERS
// ==========================================

/**
 * Voter preparation handler. Generates browser-side cryptographic objects and populates math inspector.
 */
async function handlePrepareVote() {
    const tokenInput = document.getElementById("token-input").value.trim();
    const checkedOption = document.querySelector('input[name="vote-choice"]:checked');
    
    if (!tokenInput) {
        showModal("Validation Error", "Please enter a valid single-use classroom token.", false);
        return;
    }
    
    if (!checkedOption) {
        showModal("Validation Error", "Please select a vote option (YES or NO).", false);
        return;
    }
    
    if (!serverParams.u) {
        showModal("Cryptographic Error", "Parameters not loaded from server. Please wait or reload.", false);
        return;
    }
    
    const voteVal = checkedOption.value; // "1" or "0"
    const btn = document.getElementById("btn-prepare-vote");
    btn.disabled = true;
    btn.textContent = "Calculating Proofs...";
    
    try {
        preparedPayload = await generateVotePayload(tokenInput, voteVal, serverParams.u);
        
        // Populating the Math Inspector UI
        document.getElementById("inspect-b").textContent = `${preparedPayload.meta.b} (${preparedPayload.meta.b === "1" ? 'YES' : 'NO'})`;
        document.getElementById("inspect-r").textContent = preparedPayload.meta.r;
        
        document.getElementById("inspect-c1").textContent = preparedPayload.ciphertext.c1;
        document.getElementById("inspect-c2").textContent = preparedPayload.ciphertext.c2;
        
        document.getElementById("inspect-a0").textContent = preparedPayload.proof.A0;
        document.getElementById("inspect-b0").textContent = preparedPayload.proof.B0;
        document.getElementById("inspect-a1").textContent = preparedPayload.proof.A1;
        document.getElementById("inspect-b1").textContent = preparedPayload.proof.B1;
        
        document.getElementById("inspect-ch").textContent = preparedPayload.meta.ch;
        document.getElementById("inspect-ch0").textContent = preparedPayload.proof.challenge_0;
        document.getElementById("inspect-ch1").textContent = preparedPayload.proof.challenge_1;
        
        const badge = document.getElementById("inspect-ch-check");
        badge.textContent = "TRUE";
        
        document.getElementById("inspect-s0").textContent = preparedPayload.proof.response_0;
        document.getElementById("inspect-s1").textContent = preparedPayload.proof.response_1;
        
        // JSON preview
        const apiPayload = {
            token: preparedPayload.token,
            ciphertext: preparedPayload.ciphertext,
            proof: {
                challenge_0: preparedPayload.proof.challenge_0,
                challenge_1: preparedPayload.proof.challenge_1,
                response_0: preparedPayload.proof.response_0,
                response_1: preparedPayload.proof.response_1,
                A0: preparedPayload.proof.A0,
                B0: preparedPayload.proof.B0,
                A1: preparedPayload.proof.A1,
                B1: preparedPayload.proof.B1
            }
        };
        document.getElementById("inspect-json").textContent = JSON.stringify(apiPayload, null, 2);
        
        // Reveal panel
        document.getElementById("crypto-inspector").classList.remove("hidden");
        
    } catch (err) {
        console.error(err);
        showModal("Cryptographic Failure", "Browser failed modular arithmetic computations. Please try again.", false);
    } finally {
        btn.disabled = false;
        btn.textContent = "⚙️ Generate Cryptographic Payload";
    }
}

/**
 * Casts the prepared voter payload securely.
 */
async function handleSubmitVote() {
    if (!preparedPayload) return;
    
    const apiPayload = {
        token: preparedPayload.token,
        ciphertext: preparedPayload.ciphertext,
        proof: {
            challenge_0: preparedPayload.proof.challenge_0,
            challenge_1: preparedPayload.proof.challenge_1,
            response_0: preparedPayload.proof.response_0,
            response_1: preparedPayload.proof.response_1,
            A0: preparedPayload.proof.A0,
            B0: preparedPayload.proof.B0,
            A1: preparedPayload.proof.A1,
            B1: preparedPayload.proof.B1
        }
    };
    
    const btn = document.getElementById("btn-submit-vote");
    btn.disabled = true;
    btn.textContent = "Transmitting Payload...";
    
    try {
        const res = await fetch("/api/election/vote", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(apiPayload)
        });
        
        const data = await res.json();
        if (res.ok) {
            showModal("Ballot Accepted", "Your encrypted vote has been validated via NIZK and homomorphically accumulated on the server ledger!", true);
            
            // Clear inputs
            document.getElementById("token-input").value = "";
            const checkedChoice = document.querySelector('input[name="vote-choice"]:checked');
            if (checkedChoice) checkedChoice.checked = false;
            document.getElementById("crypto-inspector").classList.add("hidden");
            preparedPayload = null;
            
            fetchState();
        } else {
            showModal("Ballot Rejected", data.detail || "Server rejected vote payload verification.", false);
        }
    } catch (err) {
        showModal("Transmission Error", "Failed to connect to the voting server API.", false);
    } finally {
        btn.disabled = false;
        btn.textContent = "🛡️ Cast Encrypted Vote securely";
    }
}

// ==========================================
// 5. ADMIN CONTROL MODULE ACTIONS
// ==========================================

/**
 * Admin: Generate Tokens
 */
async function handleGenerateTokens() {
    const countInput = document.getElementById("token-count-input");
    const count = parseInt(countInput.value) || 5;
    
    try {
        const res = await fetch("/api/election/tokens", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ count: count })
        });
        
        if (res.ok) {
            const data = await res.json();
            showModal("Tokens Generated", `Successfully generated ${data.tokens.length} single-use classroom voting tokens. They are now registered and active!`, true);
            fetchState();
        } else {
            if (res.status === 401) {
                showModal("Access Denied", "Authentication required to generate tokens.", false);
            } else {
                showModal("Error", "Server failed to generate tokens.", false);
            }
        }
    } catch (err) {
        showModal("Error", "Failed to reach server API.", false);
    }
}

/**
 * Admin: Close Election & Decrypt Tally
 */
async function handleCloseElection() {
    try {
        const res = await fetch("/api/election/close", { method: "POST" });
        if (res.ok) {
            const data = await res.json();
            showModal("Election Closed", `Voting is now closed. The server has decrypted the accumulated ciphertexts successfully. YES: ${data.yes_tally}, NO: ${data.no_tally}`, true);
            renderResults(data);
            fetchState();
        } else {
            if (res.status === 401) {
                showModal("Access Denied", "Authentication required to close the election.", false);
            } else {
                showModal("Error", "Server failed to close and decrypt tally.", false);
            }
        }
    } catch (err) {
        showModal("Error", "Failed to reach server API.", false);
    }
}

/**
 * Admin: Reset Election
 */
async function handleResetElection() {
    if (!confirm("Are you absolutely sure you want to reset the election? All current active tokens, verification logs, and tallies will be permanently wiped!")) {
        return;
    }
    
    try {
        const res = await fetch("/api/election/reset", { method: "POST" });
        if (res.ok) {
            showModal("Election Reset", "The election has been cleanly reset. Wiped in-memory databases and generated fresh cryptographic parameters and keypairs.", true);
            
            // Relock results card
            const lockOverlay = document.getElementById("results-lock-overlay");
            const activeContent = document.getElementById("results-active-content");
            if (lockOverlay) lockOverlay.classList.remove("hidden");
            if (activeContent) activeContent.classList.add("hidden");
            
            fetchState();
        } else {
            if (res.status === 401) {
                showModal("Access Denied", "Authentication required to reset the election.", false);
            } else {
                showModal("Error", "Server failed to reset election.", false);
            }
        }
    } catch (err) {
        showModal("Error", "Failed to reach server API.", false);
    }
}

// ==========================================
// 6. INITIALIZATION
// ==========================================

async function init() {
    try {
        // Load Public parameters
        const res = await fetch("/api/election/parameters");
        const params = await res.json();
        
        serverParams.u = BigInt(params.u);
        
        const pElem = document.getElementById("val-p");
        if (pElem) pElem.textContent = params.p;
        
        const qElem = document.getElementById("val-q");
        if (qElem) qElem.textContent = params.q;
        
        const gElem = document.getElementById("val-g");
        if (gElem) gElem.textContent = params.g;
        
        const uElem = document.getElementById("val-u");
        if (uElem) uElem.textContent = params.u;
        
        // Run initial state pull
        await fetchState();
        
        // Setup polling every 3 seconds
        setInterval(fetchState, 3000);
        
    } catch (err) {
        console.error("Failed to initialize parameters:", err);
    }
    
    // Bind Voter Events
    const btnPrepare = document.getElementById("btn-prepare-vote");
    if (btnPrepare) btnPrepare.addEventListener("click", handlePrepareVote);
    
    const btnSubmit = document.getElementById("btn-submit-vote");
    if (btnSubmit) btnSubmit.addEventListener("click", handleSubmitVote);
    
    // Bind Admin Events
    const btnGenTokens = document.getElementById("btn-generate-tokens");
    if (btnGenTokens) btnGenTokens.addEventListener("click", handleGenerateTokens);
    
    const btnClose = document.getElementById("btn-close-election");
    if (btnClose) btnClose.addEventListener("click", handleCloseElection);
    
    const btnReset = document.getElementById("btn-reset-election");
    if (btnReset) btnReset.addEventListener("click", handleResetElection);
    
    // Modal controls
    const closeBtn = document.getElementById("modal-close-btn");
    if (closeBtn) closeBtn.addEventListener("click", closeModal);
}

// Run startup hook
window.addEventListener("DOMContentLoaded", init);
