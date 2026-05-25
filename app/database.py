import datetime
from app.crypto import generate_keypair, p

# In-memory dictionaries representing the state of the voting application
ELECTION_STATE = {
    "public_key_u": None,
    "private_key_alpha": None,
    "aggregated_c1": 1,
    "aggregated_c2": 1,
    "total_votes_cast": 0,
    "is_closed": False
}

# Maps token_id (str) -> is_used (bool)
TOKEN_REGISTRY = {}

# List of dicts representing verification logs:
# { "timestamp": str, "token": str, "c1": str, "c2": str, "status": str }
VOTE_LOGS = []


def init_election():
    """
    Initializes/Resets a fresh election.
    Generates a new ElGamal key pair, resets the accumulator, clears tokens, and wipes logs.
    """
    global ELECTION_STATE, TOKEN_REGISTRY, VOTE_LOGS
    alpha, u = generate_keypair()
    
    ELECTION_STATE["public_key_u"] = u
    ELECTION_STATE["private_key_alpha"] = alpha
    ELECTION_STATE["aggregated_c1"] = 1
    ELECTION_STATE["aggregated_c2"] = 1
    ELECTION_STATE["total_votes_cast"] = 0
    ELECTION_STATE["is_closed"] = False
    
    TOKEN_REGISTRY.clear()
    VOTE_LOGS.clear()
    return ELECTION_STATE


def add_token(token_id: str) -> bool:
    """
    Registers a new single-use token in the election.
    Returns True if registered successfully, or False if token already exists.
    """
    if token_id in TOKEN_REGISTRY:
        return False
    TOKEN_REGISTRY[token_id] = False
    return True


def use_token(token_id: str) -> bool:
    """
    Consumes a token, marking it as used.
    Returns True if token exists and was not yet used, otherwise False.
    """
    if token_id not in TOKEN_REGISTRY or TOKEN_REGISTRY[token_id]:
        return False
    TOKEN_REGISTRY[token_id] = True
    return True


def update_accumulator(c1: int, c2: int):
    """
    Multiplies the incoming ciphertext components homomorphically into the election accumulator.
    All operations are computed modulo p.
    """
    global ELECTION_STATE
    ELECTION_STATE["aggregated_c1"] = (ELECTION_STATE["aggregated_c1"] * c1) % p
    ELECTION_STATE["aggregated_c2"] = (ELECTION_STATE["aggregated_c2"] * c2) % p
    ELECTION_STATE["total_votes_cast"] += 1


def close_election():
    """
    Closes the current election, freezing vote accumulation.
    """
    global ELECTION_STATE
    ELECTION_STATE["is_closed"] = True


def log_transaction(token: str, c1: int, c2: int, status: str):
    """
    Logs an incoming vote transaction for visual tracking on the live ledger dashboard.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    VOTE_LOGS.append({
        "timestamp": timestamp,
        "token": token,
        "c1": str(c1),
        "c2": str(c2),
        "status": status
    })


def get_election_state() -> dict:
    """
    Returns public components of the election state.
    Excludes the private key alpha for security.
    """
    return {
        "public_key_u": str(ELECTION_STATE["public_key_u"]),
        "aggregated_c1": str(ELECTION_STATE["aggregated_c1"]),
        "aggregated_c2": str(ELECTION_STATE["aggregated_c2"]),
        "total_votes_cast": ELECTION_STATE["total_votes_cast"],
        "is_closed": ELECTION_STATE["is_closed"],
    }
