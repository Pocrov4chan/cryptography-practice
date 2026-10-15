import hashlib
import shutil
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
WORK_DIR = ROOT / "out" / "case1"

MIRROR = WORK_DIR / "mirror"                       # download server: the attacker can take this over
RELEASE_FILE = MIRROR / "release-v1.0.tar.gz"
SIGNATURE_FILE = MIRROR / "release-v1.0.tar.gz.sig"
CHECKSUM_FILE = MIRROR / "release-v1.0.tar.gz.sha256"

PUBLIC_KEY_FILE = WORK_DIR / "trusted" / "developer-public-key.pem"   # from a trusted place, NOT the mirror


def print_step(title):
    print(f"\n=== {title} ===")


def ok_or_fail(passed):
    return "OK" if passed else "FAIL"


def short_hex(data):
    return data[:16].hex() + "..."


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def is_signature_valid(public_key, signature, data):
    # verify() returns None if the signature is valid and raises InvalidSignature if not
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False


def save_public_key(public_key, path):
    pem = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    path.write_bytes(pem)


def load_public_key(path):
    return serialization.load_pem_public_key(path.read_bytes())


def user_verifies_download(public_key):
    release = RELEASE_FILE.read_bytes()
    signature = SIGNATURE_FILE.read_bytes()
    published_checksum = CHECKSUM_FILE.read_text()

    checksum_matches = sha256_hex(release) == published_checksum
    signature_valid = is_signature_valid(public_key, signature, release)

    print(f"  checksum check:  {ok_or_fail(checksum_matches)}")
    print(f"  signature check: {ok_or_fail(signature_valid)}")


def main():
    shutil.rmtree(WORK_DIR, ignore_errors=True)
    MIRROR.mkdir(parents=True)
    PUBLIC_KEY_FILE.parent.mkdir(parents=True)

    print_step("Step 1. Developer generates an Ed25519 key pair")
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    save_public_key(public_key, PUBLIC_KEY_FILE)
    print(f"  public key (32 bytes): {public_key.public_bytes_raw().hex()}")
    print(f"  published at: {PUBLIC_KEY_FILE.relative_to(ROOT)}")

    print_step("Step 2. Developer signs the release and uploads release + signature + checksum to the mirror")
    release = b"release v1.0: pretend these bytes are the app's files"
    signature = private_key.sign(release)
    RELEASE_FILE.write_bytes(release)
    SIGNATURE_FILE.write_bytes(signature)
    CHECKSUM_FILE.write_text(sha256_hex(release))
    print(f"  {RELEASE_FILE.relative_to(ROOT)}")
    print(f"  {SIGNATURE_FILE.relative_to(ROOT)}  (64 bytes: {short_hex(signature)})")
    print(f"  {CHECKSUM_FILE.relative_to(ROOT)}")

    print_step("Step 3. User downloads the files and verifies them with the developer's public key")
    trusted_public_key = load_public_key(PUBLIC_KEY_FILE)
    user_verifies_download(trusted_public_key)

    print_step("Step 4. Why not just a checksum? An attacker takes over the mirror")
    malware = b"release v1.0: pretend these bytes are the app's files + a backdoor"
    RELEASE_FILE.write_bytes(malware)
    CHECKSUM_FILE.write_text(sha256_hex(malware))     # anyone can recompute a checksum: it needs no key
    user_verifies_download(trusted_public_key)
    print("  -> the checksum is fooled: it only proves integrity")
    print("  -> the signature is not:   it proves integrity + authenticity")

    print_step("Step 5. Change a single byte of the genuine release")
    tampered_release = release.replace(b"v1.0", b"v1.1")
    signature_valid = is_signature_valid(trusted_public_key, signature, tampered_release)
    print(f"  sha256 of the original: {sha256_hex(release)[:32]}...")
    print(f"  sha256 of the tampered: {sha256_hex(tampered_release)[:32]}...")
    print(f"  signature check: {ok_or_fail(signature_valid)}")

    print_step("Step 6. Attacker signs the malware with their own key pair")
    attacker_private_key = Ed25519PrivateKey.generate()
    attacker_public_key = attacker_private_key.public_key()
    attacker_signature = attacker_private_key.sign(malware)
    valid_with_attacker_key = is_signature_valid(attacker_public_key, attacker_signature, malware)
    valid_with_developer_key = is_signature_valid(trusted_public_key, attacker_signature, malware)
    print(f"  check with the attacker's public key:  {ok_or_fail(valid_with_attacker_key)}")
    print(f"  check with the developer's public key: {ok_or_fail(valid_with_developer_key)}")

    print_step("Step 7. Where does the nonce come from? Sign twice and compare")
    # Ed25519 doesn't take the nonce r from the random generator, it computes it:
    #     r = SHA-512(secret prefix || message)            the secret prefix comes from the private key
    #     R = r * B                                         the first half of the signature
    #     S = (r + SHA-512(R || A || message) * a) mod L    the second half
    # Same message -> same r -> identical signature. A broken RNG can't make it reuse a nonce (the case 2 bug).
    first_signature = private_key.sign(release)
    second_signature = private_key.sign(release)
    other_release_signature = private_key.sign(b"release v1.1")
    first_nonce_part = first_signature[:32]       # R, the part that comes from the nonce
    second_nonce_part = second_signature[:32]
    other_nonce_part = other_release_signature[:32]
    print(f"  release v1.0, signed once:  R = {short_hex(first_nonce_part)}")
    print(f"  release v1.0, signed again: R = {short_hex(second_nonce_part)}")
    print(f"  release v1.1:               R = {short_hex(other_nonce_part)}")
    print(f"  same message  -> identical signatures: {first_signature == second_signature}")
    print(f"  other message -> different nonce:      {first_nonce_part != other_nonce_part}")


if __name__ == "__main__":
    main()
