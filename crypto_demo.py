"""
VulnScan Pro — Crypto Module (crypto-demo)
=============================================
Educational demo of weak-crypto attacks, used alongside VulnApp.

Contains 3 tools in one file:
  1. Hash Cracker      — MD5/SHA1 dictionary + brute-force cracking
  2. Caesar Breaker     — auto-decrypt Caesar cipher via frequency analysis
  3. JWT Forge Demo     — forge a JWT using a known/weak HS256 secret

WARNING: For educational / authorized-testing use only.

Run:
    python crypto_demo.py
"""

import hashlib
import itertools
import string
import json
import base64
import hmac

try:
    import jwt  # pip install PyJWT
    HAS_PYJWT = True
except ImportError:
    HAS_PYJWT = False


# ════════════════════════════════════════════════════════
# 1. HASH CRACKER — MD5 / SHA1 / SHA256
# ════════════════════════════════════════════════════════

COMMON_WORDLIST = [
    "password", "123456", "admin", "letmein", "qwerty", "welcome",
    "monkey", "dragon", "master", "abc123", "iloveyou", "trustno1",
    "1234", "12345", "password123", "admin123", "root", "toor",
    "test", "guest", "changeme", "secret", "login", "princess",
]


def hash_string(plaintext, algo="md5"):
    """Hash a plaintext string with the chosen algorithm."""
    h = hashlib.new(algo)
    h.update(plaintext.encode("utf-8"))
    return h.hexdigest()


def crack_dictionary(target_hash, algo="md5", wordlist=None):
    """
    Try every word in the wordlist against the target hash.
    Returns the cracked plaintext, or None if not found.
    """
    wordlist = wordlist or COMMON_WORDLIST
    target_hash = target_hash.lower().strip()

    for word in wordlist:
        if hash_string(word, algo) == target_hash:
            return word
    return None


def crack_bruteforce(target_hash, algo="md5", charset=None, max_length=4):
    """
    Brute-force every combination up to max_length using charset.
    WARNING: grows exponentially — keep max_length small (<=5) for digits/lower.
    """
    charset = charset or (string.ascii_lowercase + string.digits)
    target_hash = target_hash.lower().strip()

    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = "".join(combo)
            if hash_string(candidate, algo) == target_hash:
                return candidate
    return None


def demo_hash_cracker():
    print("\n" + "═" * 60)
    print(" 1. HASH CRACKER DEMO (MD5 vs salted bcrypt-style)")
    print("═" * 60)

    targets = {
        "admin": hash_string("admin", "md5"),
        "bob":   hash_string("1234", "md5"),
    }

    for user, h in targets.items():
        print(f"\n[*] Target hash for '{user}': {h}")
        cracked = crack_dictionary(h, "md5")
        if cracked:
            print(f"    [+] CRACKED via dictionary attack -> '{cracked}'")
        else:
            print("    [-] Not in wordlist, trying brute-force (digits, len<=4)...")
            cracked = crack_bruteforce(h, "md5", charset=string.digits, max_length=4)
            print(f"    [+] CRACKED via brute-force -> '{cracked}'" if cracked else "    [-] Not cracked.")

    print("\n[i] Why this works: MD5 is fast + unsalted, so identical passwords")
    print("    always produce identical hashes -> trivially reversible via lookup.")
    print("[i] Mitigation: use bcrypt/argon2 (slow, salted, adaptive cost factor).")
    print("    Demonstration (NOT reversible the same way):")

    try:
        import bcrypt
        salted = bcrypt.hashpw(b"admin", bcrypt.gensalt())
        print(f"    bcrypt('admin') -> {salted.decode()}  (unique salt every time, slow to brute-force)")
    except ImportError:
        print("    [bcrypt not installed — pip install bcrypt to see live comparison]")


# ════════════════════════════════════════════════════════
# 2. CAESAR CIPHER — ENCODE + AUTO-BREAK
# ════════════════════════════════════════════════════════

ENGLISH_FREQ_ORDER = "etaoinshrdlcumwfgypbvkjxqz"


def caesar_encrypt(text, shift):
    """Encrypt text with a Caesar shift (letters only; preserves case/punctuation)."""
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


def _score_text(text):
    text = text.lower()
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0
    score = 0
    for ch in letters:
        idx = ENGLISH_FREQ_ORDER.find(ch)
        weight = (26 - idx) if idx != -1 else 0
        score += weight
    return score / len(letters)


def caesar_break(ciphertext):
    """
    Try all 26 shifts, score each candidate plaintext via letter frequency,
    return the best guess (shift, plaintext) sorted by descending score.
    """
    candidates = []
    for shift in range(26):
        plain = caesar_decrypt(ciphertext, shift)
        score = _score_text(plain)
        candidates.append((shift, plain, score))
    candidates.sort(key=lambda x: x[2], reverse=True)
    return candidates


def demo_caesar_breaker():
    print("\n" + "═" * 60)
    print(" 2. CAESAR CIPHER — AUTO-BREAK DEMO")
    print("═" * 60)

    secret_message = "Meet me at the old bridge at midnight"
    shift_used = 7
    cipher = caesar_encrypt(secret_message, shift_used)

    print(f"\n[*] Original message : {secret_message}")
    print(f"[*] Encrypted (shift={shift_used}): {cipher}")

    print("\n[*] Attacker only sees ciphertext. Breaking via frequency analysis...")
    results = caesar_break(cipher)

    print("\n    Top 3 candidate shifts (ranked by English letter-frequency score):")
    for shift, plain, score in results[:3]:
        print(f"      shift={shift:2d}  score={score:5.2f}  ->  {plain}")

    best_shift, best_plain, _ = results[0]
    print(f"\n[+] Best guess: shift={best_shift} -> '{best_plain}'")
    print("[i] Why this works: Caesar cipher has only 26 possible keys, and natural")
    print("    language has a predictable letter-frequency fingerprint — easy to brute-force.")
    print("[i] Mitigation: never use classical substitution ciphers for real security;")
    print("    use AES-256/ChaCha20 with proper key management instead.")


# ════════════════════════════════════════════════════════
# 3. JWT FORGE DEMO — WEAK HS256 SECRET
# ════════════════════════════════════════════════════════

WEAK_JWT_SECRET = "jwt_secret_123"


def jwt_encode_manual(payload, secret):
    """
    Manually build an HS256 JWT (no PyJWT dependency) to show students
    exactly what's happening under the hood.
    """
    header = {"alg": "HS256", "typ": "JWT"}

    def b64url(data: dict) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header_b64  = b64url(header)
    payload_b64 = b64url(payload)
    signing_input = f"{header_b64}.{payload_b64}".encode()

    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def jwt_decode_manual(token, secret):
    """Verify + decode a manually-built (or PyJWT) HS256 token."""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        return None, "Malformed token"

    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected_sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).rstrip(b"=").decode()

    if not hmac.compare_digest(sig_b64, expected_sig_b64):
        return None, "Invalid signature"

    pad = "=" * (-len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + pad))
    return payload, None


def demo_jwt_forge():
    print("\n" + "═" * 60)
    print(" 3. JWT FORGE DEMO — WEAK SECRET ATTACK")
    print("═" * 60)

    user_payload = {"user_id": 2, "username": "alice", "role": "user"}
    user_token = jwt_encode_manual(user_payload, WEAK_JWT_SECRET)
    print(f"\n[*] Legit user token (role=user):\n    {user_token}")

    common_secrets = ["secret", "jwt_secret_123", "changeme", "123456", "key"]
    print(f"\n[*] Attacker tries common secrets: {common_secrets}")
    recovered_secret = None
    for candidate in common_secrets:
        payload, err = jwt_decode_manual(user_token, candidate)
        if payload is not None:
            recovered_secret = candidate
            break
    print(f"[+] Secret recovered: '{recovered_secret}'" if recovered_secret else "[-] Secret not found.")

    if recovered_secret:
        forged_payload = {"user_id": 999, "username": "attacker", "role": "admin", "forged": True}
        forged_token = jwt_encode_manual(forged_payload, recovered_secret)
        print(f"\n[+] Forged ADMIN token using recovered secret:\n    {forged_token}")

        verified, err = jwt_decode_manual(forged_token, WEAK_JWT_SECRET)
        if verified:
            print(f"\n[!] Server accepts forged token! Decoded payload: {verified}")
            print("    -> This is exactly what vulnapp.py's /api/jwt/admin endpoint will accept.")

    print("\n[i] Why this works: JWT signatures only prove the secret was known when")
    print("    signing — if the secret is weak/guessable/hardcoded, anyone can forge any payload.")
    print("[i] Mitigation: use a long random secret (>=256 bits) from a secrets manager,")
    print("    rotate it regularly, and never hardcode it in source code.")

    if HAS_PYJWT:
        pyjwt_token = jwt.encode(user_payload, WEAK_JWT_SECRET, algorithm="HS256")
        if isinstance(pyjwt_token, bytes):
            pyjwt_token = pyjwt_token.decode()
        match = "✓ matches manual implementation" if pyjwt_token.split(".")[:2] == user_token.split(".")[:2] else "✗ differs"
        print(f"\n[i] PyJWT cross-check (header+payload): {match}")


# ════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("VulnScan Pro — Crypto Module Demo")
    print("For educational / authorized-testing use only.")
    demo_hash_cracker()
    demo_caesar_breaker()
    demo_jwt_forge()
    print("\n" + "═" * 60)
    print(" Done. All 3 demos ran successfully.")
    print("═" * 60)
