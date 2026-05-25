import secrets
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware

from app.crypto import verify_proof, decrypt_tally, p, q, g
from app.database import (
    ELECTION_STATE,
    TOKEN_REGISTRY,
    VOTE_LOGS,
    init_election,
    add_token,
    use_token,
    update_accumulator,
    close_election,
    log_transaction,
    get_election_state,
)
from app.schemas import VotePayloadSchema, TokenBatchSchema

# Generate Admin Credentials dynamically at server startup
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = secrets.token_urlsafe(8)

app = FastAPI(
    title="Cryptographic Classroom Voting System",
    description="Electronic Voting prototype using Homomorphic ElGamal and 1-out-of-2 NIZK proofs",
    version="1.0.0"
)

# Enable CORS for external testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# HTTP Basic security dependency
security = HTTPBasic()


def get_admin_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    """
    Dependency to verify HTTP Basic Authentication for Admin actions.
    """
    correct_username = secrets.compare_digest(credentials.username, ADMIN_USERNAME)
    correct_password = secrets.compare_digest(credentials.password, ADMIN_PASSWORD)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect admin username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


@app.on_event("startup")
def startup_event():
    """
    FastAPI startup lifecycle hook.
    Initializes a fresh election and prints the admin credentials.
    """
    init_election()
    
    # Render a beautiful credentials card in stdout
    border = "=" * 70
    print("\n" + border)
    print(" 🛡️  HOMOMORPHIC ELGAMAL VOTING SYSTEM - STARTUP SUCCESSFUL")
    print(border)
    print("  ADMIN DASHBOARD LOGIN CREDENTIALS:")
    print(f"    - URL:       http://localhost:8000/admin")
    print(f"    - Username:  {ADMIN_USERNAME}")
    print(f"    - Password:  {ADMIN_PASSWORD}")
    print(border)
    print("  Note: Client dashboard is open to anyone at http://localhost:8000/")
    print(border + "\n")


# ==========================================
# 1. PAGE ROUTES (HTML Delivery)
# ==========================================

@app.get("/", response_class=FileResponse)
def read_voter_client():
    """
    Serves the Voter Client Dashboard page.
    """
    return FileResponse("static/index.html")


@app.get("/admin", response_class=FileResponse)
def read_admin_dashboard(username: str = Depends(get_admin_credentials)):
    """
    Serves the Admin Panel page, protected by Basic Authentication.
    """
    return FileResponse("static/admin.html")


# ==========================================
# 2. PUBLIC ELECTION ENDPOINTS
# ==========================================

@app.get("/api/election/parameters")
def get_parameters():
    """
    Public endpoint. Returns the cryptographic parameters (p, q, g) and public key u.
    """
    u = ELECTION_STATE["public_key_u"]
    if u is None:
        raise HTTPException(status_code=500, detail="Election parameters not initialized")
    return {
        "p": str(p),
        "q": str(q),
        "g": g,
        "u": str(u)
    }


@app.get("/api/election/state")
def get_state():
    """
    Public endpoint. Returns the current status of the accumulator, cast count, and log feed.
    """
    state = get_election_state()
    # Provide the tokens list and logs to render the ledger and admin stats in real-time
    state["tokens"] = TOKEN_REGISTRY
    state["logs"] = VOTE_LOGS
    return state


@app.post("/api/election/vote")
def cast_vote(payload: VotePayloadSchema):
    """
    Public endpoint. Casts a voter-encrypted vote.
    Validation sequence:
      1. Check election is open.
      2. Check token exists and is unused.
      3. Verify NIZK proof.
      4. Homomorphically aggregate c1, c2, consume token, and log status.
    """
    # 1. Verify election status
    if ELECTION_STATE["is_closed"]:
        log_transaction(payload.token, payload.ciphertext.c1, payload.ciphertext.c2, "REJECTED (ELECTION CLOSED)")
        raise HTTPException(status_code=400, detail="Voting has closed for this election")

    # 2. Verify token validity
    token = payload.token
    if token not in TOKEN_REGISTRY:
        log_transaction(payload.token, payload.ciphertext.c1, payload.ciphertext.c2, "REJECTED (INVALID TOKEN)")
        raise HTTPException(status_code=400, detail="Invalid token. Please obtain a registered token.")

    if TOKEN_REGISTRY[token]:
        log_transaction(payload.token, payload.ciphertext.c1, payload.ciphertext.c2, "REJECTED (TOKEN REPLAY)")
        raise HTTPException(status_code=400, detail="Token has already been used to cast a vote")

    # 3. Verify NIZK proof
    u = ELECTION_STATE["public_key_u"]
    c1 = payload.ciphertext.c1
    c2 = payload.ciphertext.c2
    proof_dict = payload.proof.dict(by_alias=True)

    is_valid_proof = verify_proof(u, c1, c2, proof_dict)
    if not is_valid_proof:
        log_transaction(token, c1, c2, "REJECTED (INVALID NIZK PROOF)")
        raise HTTPException(status_code=400, detail="Cryptographic verification failed: Invalid NIZK proof")

    # 4. Success Pipeline: Consume token, aggregate values, and log transaction
    use_token(token)
    update_accumulator(c1, c2)
    log_transaction(token, c1, c2, "VALIDATED")

    return {"status": "success", "message": "Vote verified and successfully registered homomorphically"}


# ==========================================
# 3. SECURED ADMIN ENDPOINTS
# ==========================================

@app.post("/api/election/tokens")
def generate_tokens(batch: TokenBatchSchema, username: str = Depends(get_admin_credentials)):
    """
    Admin endpoint. Generates a batch of unique, single-use classroom tokens.
    """
    new_tokens = []
    for _ in range(batch.count):
        t = f"TKN-{secrets.token_hex(3).upper()}"
        while not add_token(t):  # Ensure token uniqueness
            t = f"TKN-{secrets.token_hex(3).upper()}"
        new_tokens.append(t)
    return {"status": "success", "tokens": new_tokens}


@app.post("/api/election/close")
def trigger_close(username: str = Depends(get_admin_credentials)):
    """
    Admin endpoint. Closes the election and decypts the homomorphic accumulator.
    """
    if ELECTION_STATE["is_closed"]:
        # If already closed, simply perform decrypt again and return
        pass
    else:
        close_election()

    # Perform Decryption
    alpha = ELECTION_STATE["private_key_alpha"]
    C1 = ELECTION_STATE["aggregated_c1"]
    C2 = ELECTION_STATE["aggregated_c2"]
    total = ELECTION_STATE["total_votes_cast"]

    yes_tally = decrypt_tally(alpha, C1, C2, total)
    if yes_tally == -1:
        raise HTTPException(status_code=500, detail="Decryption failure: accumulator values corrupted or invalid")

    no_tally = total - yes_tally

    return {
        "status": "closed",
        "total_votes_cast": total,
        "yes_tally": yes_tally,
        "no_tally": no_tally,
        "accumulator": {
            "c1": str(C1),
            "c2": str(C2)
        }
    }


@app.post("/api/election/reset")
def trigger_reset(username: str = Depends(get_admin_credentials)):
    """
    Admin endpoint. Wipes current state and initializes a new voting environment.
    """
    init_election()
    return {"status": "success", "message": "Election reset successfully. Generated new cryptographic keys."}


# Mount the static files folder so stylesheets, script, and web elements load
app.mount("/static", StaticFiles(directory="static"), name="static")
