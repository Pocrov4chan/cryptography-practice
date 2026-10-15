import hashlib

from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_string, sigencode_strings

CURVE = SECP256k1
N = CURVE.order                       # the curve order: every number in ECDSA math is taken mod N


def print_step(title):
    print(f"\n=== {title} ===")


def message_hash(message):
    # ECDSA signs the hash of the message, read as a number (this is z)
    return int.from_bytes(hashlib.sha256(message).digest(), "big")


def sign_with_fixed_k(signing_key, message, k):
    # force the nonce k and return (r, s) as plain integers so we can do algebra on them
    r_bytes, s_bytes = signing_key.sign_digest(
        hashlib.sha256(message).digest(), k=k, sigencode=lambda r, s, order: sigencode_strings(r, s, order)
    )
    return int.from_bytes(r_bytes, "big"), int.from_bytes(s_bytes, "big")


def signature_is_valid(verifying_key, message, r, s):
    try:
        return verifying_key.verify_digest(sigencode_string(r, s, N), hashlib.sha256(message).digest())
    except Exception:
        return False


def main():
    print_step("Step 1. The victim generates a secp256k1 key pair")
    victim_key = SigningKey.generate(curve=CURVE)
    victim_public_key = victim_key.get_verifying_key()
    d_real = victim_key.privkey.secret_multiplier        # the real private key d (the attacker never sees it)
    print(f"  private key d (secret): {hex(d_real)}")

    print_step("Step 2. The broken signer reuses the SAME nonce k for two different messages")
    k = 0x1234567890ABCDEF1234567890ABCDEF                # the repeated nonce (attacker does NOT know this)
    message1 = b"Send 10 coins to Alice"
    message2 = b"Send 50 coins to Bob"
    r1, s1 = sign_with_fixed_k(victim_key, message1, k)
    r2, s2 = sign_with_fixed_k(victim_key, message2, k)
    print(f"  message 1: {message1.decode()!r}")
    print(f"  message 2: {message2.decode()!r}")
    print(f"  signature 1: r = {hex(r1)}")
    print(f"               s = {hex(s1)}")
    print(f"  signature 2: r = {hex(r2)}")
    print(f"               s = {hex(s2)}")

    print_step("Step 3. Both signatures are valid, and r1 == r2 (the tell-tale sign)")
    print(f"  signature 1 valid: {signature_is_valid(victim_public_key, message1, r1, s1)}")
    print(f"  signature 2 valid: {signature_is_valid(victim_public_key, message2, r2, s2)}")
    print(f"  r1 == r2: {r1 == r2}  <- r comes from k alone, so reusing k makes it repeat")

    print_step("Step 4. The attacker recovers the private key from the two signatures")
    # The attacker knows only the public values: the two messages and (r, s1, s2). ECDSA's signing equation is
    #
    #     s = k^-1 * (z + r*d)  mod N          z = hash(message), r is shared, d is the secret
    #
    # Written for both messages (same k, same r, different z):
    #     s1 = k^-1 * (z1 + r*d)
    #     s2 = k^-1 * (z2 + r*d)
    #
    # Subtract: r*d cancels, so k drops out on its own ->  k = (z1 - z2) * (s1 - s2)^-1   mod N
    # Put k back into the first equation         ->        d = (s1*k - z1) * r^-1          mod N
    # pow(x, -1, N) is the modular inverse: the "1/x" of mod-N arithmetic.
    z1 = message_hash(message1)
    z2 = message_hash(message2)
    k_recovered = (z1 - z2) * pow(s1 - s2, -1, N) % N
    d_recovered = (s1 * k_recovered - z1) * pow(r1, -1, N) % N
    print(f"  recovered nonce k: {hex(k_recovered)}")
    print(f"  recovered key   d: {hex(d_recovered)}")

    print_step("Step 5. Proof: the recovered key equals the real one and can forge a new signature")
    print(f"  recovered d == real d: {d_recovered == d_real}")
    forged_key = SigningKey.from_secret_exponent(d_recovered, curve=CURVE)
    evil_message = b"Send ALL coins to the attacker"
    fr, fs = sign_with_fixed_k(forged_key, evil_message, k=0xDEADBEEF)
    forged_valid = signature_is_valid(victim_public_key, evil_message, fr, fs)
    print(f"  attacker signs {evil_message.decode()!r}")
    print(f"  the victim's own public key accepts the forged signature: {forged_valid}")

    print_step("Step 6. The fixes")
    # Fix A: a fresh RANDOM k per signature. r differs, so there are no two equations to subtract.
    rr1, _ = sign_with_fixed_k(victim_key, message1, k=111111111111111111)
    rr2, _ = sign_with_fixed_k(victim_key, message2, k=222222222222222222)
    print(f"  Fix A, different k each time -> r1 != r2: {rr1 != rr2}  (but you still depend on the RNG)")

    # Fix B: RFC 6979 deterministic ECDSA. k is computed from (private key, message), like Ed25519 in case 1,
    # so no RNG is needed and k can never repeat across different messages.
    det1 = victim_key.sign_digest_deterministic(hashlib.sha256(message1).digest(), hashfunc=hashlib.sha256)
    det2 = victim_key.sign_digest_deterministic(hashlib.sha256(message2).digest(), hashfunc=hashlib.sha256)
    det_r1 = int.from_bytes(det1[: len(det1) // 2], "big")
    det_r2 = int.from_bytes(det2[: len(det2) // 2], "big")
    print(f"  Fix B, RFC 6979 deterministic -> r1 != r2: {det_r1 != det_r2}  (no RNG needed; this is the real fix)")


if __name__ == "__main__":
    main()
