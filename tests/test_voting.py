import secrets
import pytest
from fastapi.testclient import TestClient

from app.main import app, ADMIN_USERNAME, ADMIN_PASSWORD
from app.crypto import p, g, q, sha256_hash, encrypt_vote

client = TestClient(app)


def generate_client_vote(u: int, b: int, token: str) -> dict:
    """
    Simulates a client-side ElGamal encryption and 1-out-of-2 NIZK proof generation in Python.
    This provides our tests with mathematically valid ballot payloads.
    """
    # 1. Choose random blinding factor r
    r = secrets.randbelow(q - 1) + 1
    c1, c2 = encrypt_vote(u, b, r)
    
    # 2. Blinding randomness for honest branch
    w = secrets.randbelow(q - 1) + 1
    
    # Modular inverses
    g_inv = pow(g, p - 2, p)
    c1_inv = pow(c1, p - 2, p)
    c2_inv = pow(c2, p - 2, p)
    
    c2_div_g = (c2 * g_inv) % p
    c2_div_g_inv = pow(c2_div_g, p - 2, p)
    
    if b == 0:
        # Honest Branch 0, Simulated Branch 1
        A0 = pow(g, w, p)
        B0 = pow(u, w, p)
        
        ch1 = secrets.randbelow(q - 1) + 1
        s1 = secrets.randbelow(q - 1) + 1
        
        # A1 = g^s1 * c1^-ch1 mod p
        A1 = (pow(g, s1, p) * pow(c1_inv, ch1, p)) % p
        # B1 = u^s1 * (c2 / g)^-ch1 mod p
        B1 = (pow(u, s1, p) * pow(c2_div_g_inv, ch1, p)) % p
        
        ch = sha256_hash(g, u, c1, c2, A0, B0, A1, B1)
        
        ch0 = (ch - ch1) % q
        s0 = (w + ch0 * r) % q
    else:
        # Honest Branch 1, Simulated Branch 0
        ch0 = secrets.randbelow(q - 1) + 1
        s0 = secrets.randbelow(q - 1) + 1
        
        # A0 = g^s0 * c1^-ch0 mod p
        A0 = (pow(g, s0, p) * pow(c1_inv, ch0, p)) % p
        # B0 = u^s0 * c2^-ch0 mod p
        B0 = (pow(u, s0, p) * pow(c2_inv, ch0, p)) % p
        
        A1 = pow(g, w, p)
        B1 = pow(u, w, p)
        
        ch = sha256_hash(g, u, c1, c2, A0, B0, A1, B1)
        
        ch1 = (ch - ch0) % q
        s1 = (w + ch1 * r) % q
        
    return {
        "token": token,
        "ciphertext": {
            "c1": str(c1),
            "c2": str(c2)
        },
        "proof": {
            "challenge_0": str(ch0),
            "challenge_1": str(ch1),
            "response_0": str(s0),
            "response_1": str(s1),
            "A0": str(A0),
            "B0": str(B0),
            "A1": str(A1),
            "B1": str(B1),
            "type": "NIZK 0 1 FS"
        }
    }


def get_admin_auth() -> tuple[str, str]:
    return (ADMIN_USERNAME, ADMIN_PASSWORD)


def reset_election_helper():
    """
    Helper to trigger election reset using Admin credentials.
    """
    res = client.post("/api/election/reset", auth=get_admin_auth())
    assert res.status_code == 200


def get_public_key_u() -> int:
    """
    Helper to retrieve the current public key u.
    """
    res = client.get("/api/election/parameters")
    assert res.status_code == 200
    return int(res.json()["u"])


def generate_tokens_helper(count: int) -> list[str]:
    """
    Helper to generate registered classroom tokens.
    """
    res = client.post("/api/election/tokens", json={"count": count}, auth=get_admin_auth())
    assert res.status_code == 200
    return res.json()["tokens"]


# ==========================================================================
# 1. VALID VOTE (SINGLE)
# ==========================================================================
def test_valid_vote_single():
    # A. Reset Election
    reset_election_helper()
    
    # B. Fetch parameters
    u = get_public_key_u()
    
    # C. Generate token
    tokens = generate_tokens_helper(1)
    token = tokens[0]
    
    # D. Cast YES (b = 1) vote
    payload = generate_client_vote(u, b=1, token=token)
    vote_res = client.post("/api/election/vote", json=payload)
    assert vote_res.status_code == 200
    assert vote_res.json()["status"] == "success"
    
    # E. Close and Decrypt Tally
    close_res = client.post("/api/election/close", auth=get_admin_auth())
    assert close_res.status_code == 200
    data = close_res.json()
    assert data["status"] == "closed"
    assert data["total_votes_cast"] == 1
    assert data["yes_tally"] == 1
    assert data["no_tally"] == 0


# ==========================================================================
# 2. "ALL YES" SCENARIO
# ==========================================================================
def test_all_yes_scenario():
    reset_election_helper()
    u = get_public_key_u()
    
    n_voters = 5
    tokens = generate_tokens_helper(n_voters)
    
    for t in tokens:
        payload = generate_client_vote(u, b=1, token=t)
        res = client.post("/api/election/vote", json=payload)
        assert res.status_code == 200
        
    close_res = client.post("/api/election/close", auth=get_admin_auth())
    assert close_res.status_code == 200
    data = close_res.json()
    assert data["total_votes_cast"] == n_voters
    assert data["yes_tally"] == n_voters
    assert data["no_tally"] == 0


# ==========================================================================
# 3. "ALL NO" SCENARIO
# ==========================================================================
def test_all_no_scenario():
    reset_election_helper()
    u = get_public_key_u()
    
    n_voters = 4
    tokens = generate_tokens_helper(n_voters)
    
    for t in tokens:
        payload = generate_client_vote(u, b=0, token=t)
        res = client.post("/api/election/vote", json=payload)
        assert res.status_code == 200
        
    close_res = client.post("/api/election/close", auth=get_admin_auth())
    assert close_res.status_code == 200
    data = close_res.json()
    assert data["total_votes_cast"] == n_voters
    assert data["yes_tally"] == 0
    assert data["no_tally"] == n_voters


# ==========================================================================
# 4. "MIXED" SCENARIO
# ==========================================================================
def test_mixed_scenario():
    reset_election_helper()
    u = get_public_key_u()
    
    # 3 Yes, 3 No votes
    tokens = generate_tokens_helper(6)
    
    for i, t in enumerate(tokens):
        vote_choice = 1 if i < 3 else 0
        payload = generate_client_vote(u, b=vote_choice, token=t)
        res = client.post("/api/election/vote", json=payload)
        assert res.status_code == 200
        
    close_res = client.post("/api/election/close", auth=get_admin_auth())
    assert close_res.status_code == 200
    data = close_res.json()
    assert data["total_votes_cast"] == 6
    assert data["yes_tally"] == 3
    assert data["no_tally"] == 3


# ==========================================================================
# 5. TOKEN REPLAY ATTACK
# ==========================================================================
def test_token_replay_attack():
    reset_election_helper()
    u = get_public_key_u()
    
    tokens = generate_tokens_helper(1)
    token = tokens[0]
    
    # Cast first vote
    payload1 = generate_client_vote(u, b=1, token=token)
    res1 = client.post("/api/election/vote", json=payload1)
    assert res1.status_code == 200
    
    # Replay attack: attempt second vote using the exact same token
    payload2 = generate_client_vote(u, b=0, token=token)
    res2 = client.post("/api/election/vote", json=payload2)
    assert res2.status_code == 400
    assert "already been used" in res2.json()["detail"]


# ==========================================================================
# 6. MALFORMED VOTE / INVALID NIZK
# ==========================================================================
def test_malformed_vote_invalid_nizk():
    reset_election_helper()
    u = get_public_key_u()
    
    tokens = generate_tokens_helper(2)
    
    # Scenario A: Alter proof parameter (e.g. response_0)
    payload_altered = generate_client_vote(u, b=1, token=tokens[0])
    # Corrupt the proof by setting response_0 to a random number
    payload_altered["proof"]["response_0"] = "9999999999999"
    res_altered = client.post("/api/election/vote", json=payload_altered)
    assert res_altered.status_code == 400
    assert "Invalid NIZK proof" in res_altered.json()["detail"]
    
    # Scenario B: Vote value out of bounds (b = 2)
    # The encrypt_vote function in crypto only encrypts 0 or 1.
    # If we encrypt b = 2, the NIZK proof generation should fail, or if simulated manually, the server must reject.
    # Let's create a ciphertext that encrypts g^2 instead of g^1 or g^0, and mock a proof.
    r = secrets.randbelow(q - 1) + 1
    c1 = pow(g, r, p)
    # encrypt b=2
    c2 = (pow(u, r, p) * pow(g, 2, p)) % p
    
    # Generate some garbage proof commitments
    garbage_proof = {
        "token": tokens[1],
        "ciphertext": {
            "c1": str(c1),
            "c2": str(c2)
        },
        "proof": {
            "challenge_0": "123",
            "challenge_1": "456",
            "response_0": "789",
            "response_1": "1011",
            "A0": "1122",
            "B0": "3344",
            "A1": "5566",
            "B1": "7788",
            "type": "NIZK 0 1 FS"
        }
    }
    res_garbage = client.post("/api/election/vote", json=garbage_proof)
    assert res_garbage.status_code == 400
