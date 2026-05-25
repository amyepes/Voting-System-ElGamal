import hashlib
import secrets

# RFC 3526 Group 14 - 2048-bit MODP Group
HEX_P = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF"
)

# Base prime p
p = int(HEX_P, 16)

# Generator g
g = 2

# Order q of the subgroup of quadratic residues mod p.
# Since p is a safe prime, p = 2q + 1, so q = (p - 1) // 2.
q = (p - 1) // 2


def sha256_hash(*args) -> int:
    """
    Computes SHA-256 hash of the arguments string-concatenated and returns it as an integer modulo q.
    This hash function is replicated in the JS frontend to achieve client-server mathematical parity.
    """
    h = hashlib.sha256()
    for arg in args:
        h.update(str(arg).encode('utf-8'))
    return int(h.hexdigest(), 16) % q


def generate_keypair() -> tuple[int, int]:
    """
    Generates a private key alpha and a public key u = g^alpha mod p.
    alpha is chosen randomly in [1, q-1].
    """
    alpha = secrets.randbelow(q - 1) + 1
    u = pow(g, alpha, p)
    return alpha, u


def encrypt_vote(u: int, b: int, r: int) -> tuple[int, int]:
    """
    Encrypts a vote b in {0, 1} using public key u and randomness r.
    Returns the ElGamal ciphertext (c1, c2) = (g^r mod p, (u^r * g^b) mod p).
    """
    c1 = pow(g, r, p)
    c2 = (pow(u, r, p) * pow(g, b, p)) % p
    return c1, c2


def verify_proof(u: int, c1: int, c2: int, proof: dict) -> bool:
    """
    Verifies the 1-out-of-2 Sigma OR NIZK proof of validity for ElGamal ciphertext (c1, c2).
    The proof dict must contain:
      - challenge_0, challenge_1 (ch0, ch1)
      - response_0, response_1 (s0, s1)
      - A0, B0, A1, B1 (commitments)
    """
    try:
        # Extract components and convert to integers
        ch0 = int(proof["challenge_0"])
        ch1 = int(proof["challenge_1"])
        s0 = int(proof["response_0"])
        s1 = int(proof["response_1"])
        A0 = int(proof["A0"])
        B0 = int(proof["B0"])
        A1 = int(proof["A1"])
        B1 = int(proof["B1"])
    except (KeyError, ValueError, TypeError):
        return False

    # 1. Check range of values
    if not (1 <= c1 < p and 1 <= c2 < p):
        return False
    if not (1 <= A0 < p and 1 <= B0 < p and 1 <= A1 < p and 1 <= B1 < p):
        return False
    if not (0 <= ch0 < q and 0 <= ch1 < q and 0 <= s0 < q and 0 <= s1 < q):
        return False

    # 2. Check the Fiat-Shamir hash challenge constraint
    # total challenge ch = (ch0 + ch1) % q
    # Must equal H(g, u, c1, c2, A0, B0, A1, B1) % q
    computed_ch = sha256_hash(g, u, c1, c2, A0, B0, A1, B1)
    if (ch0 + ch1) % q != computed_ch:
        return False

    # 3. Verify commitments for Branch 0 (real or simulated)
    # Equation 1: g^s0 == A0 * c1^ch0 mod p
    # Equation 2: u^s0 == B0 * c2^ch0 mod p
    lhs_a0 = pow(g, s0, p)
    rhs_a0 = (A0 * pow(c1, ch0, p)) % p
    if lhs_a0 != rhs_a0:
        return False

    lhs_b0 = pow(u, s0, p)
    rhs_b0 = (B0 * pow(c2, ch0, p)) % p
    if lhs_b0 != rhs_b0:
        return False

    # 4. Verify commitments for Branch 1 (real or simulated)
    # Equation 1: g^s1 == A1 * c1^ch1 mod p
    # Equation 2: u^s1 == B1 * (c2 * g^-1)^ch1 mod p
    lhs_a1 = pow(g, s1, p)
    rhs_a1 = (A1 * pow(c1, ch1, p)) % p
    if lhs_a1 != rhs_a1:
        return False

    # Calculate g^-1 mod p
    g_inv = pow(g, p - 2, p)
    c2_div_g = (c2 * g_inv) % p

    lhs_b1 = pow(u, s1, p)
    rhs_b1 = (B1 * pow(c2_div_g, ch1, p)) % p
    if lhs_b1 != rhs_b1:
        return False

    return True


def decrypt_tally(alpha: int, C1: int, C2: int, max_votes: int) -> int:
    """
    Decrypts the homomorphically aggregated ciphertext (C1, C2) by solving the discrete logarithm.
    Since C2 / (C1^alpha) == g^tally mod p, and 0 <= tally <= max_votes,
    we can find tally by brute force.
    """
    if max_votes < 0:
        return 0

    # V = C2 / (C1^alpha) mod p
    c1_alpha = pow(C1, alpha, p)
    c1_alpha_inv = pow(c1_alpha, p - 2, p)
    target = (C2 * c1_alpha_inv) % p

    # Brute-force search in [0, max_votes]
    current_val = 1  # g^0 mod p
    for k in range(max_votes + 1):
        if current_val == target:
            return k
        current_val = (current_val * g) % p

    # Fallback/Error in case no match is found (should not happen for valid votes)
    return -1
