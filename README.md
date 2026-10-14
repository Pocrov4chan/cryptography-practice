# Cryptography in Application Security

Two sample demos plus a test of an open-source crypto tool, each showing one guarantee —
**integrity**, **authenticity**, **confidentiality** — and what breaks when a primitive is misused.

| Part | What it is | Guarantee shown | Lesson |
|---|---|---|---|
| Case 1 | Ed25519 release signing | integrity + authenticity | a checksum stops accidents, a signature stops attackers |
| Case 2 | ECDSA nonce reuse | authenticity, then broken | reuse a nonce once and the private key leaks |
| restic | encrypted backup tool | all three | tampering with a backup is always detectable |

The three parts tell one story: a keyless primitive (a hash) catches accidents, a keyed primitive (a signature or a
MAC) catches attackers, and every one of them depends on a nonce/key being used correctly.

## Setup

Uses [uv](https://docs.astral.sh/uv/). Dependencies: `cryptography` (Ed25519) and `ecdsa` (ECDSA with a chosen `k`).

```bash
uv run app/case1_ed25519_release_signing.py
uv run app/case2_ecdsa_nonce_reuse.py
# restic: see "Part 3" below. Install: brew install restic  (Fedora: sudo dnf install restic)
```

Each script runs its whole demo end to end and prints numbered steps. Captured outputs are in `results/`.

> Note on `ecdsa`: it's used only because it lets us force a chosen nonce `k`. It is not side-channel hardened;
> production code should use `cryptography` or libsecp256k1.

---

## Case 1 — Ed25519 software-release signing

**Scenario.** A developer publishes an app on a download mirror. Users want to be sure the file wasn't changed and
really came from the developer. The developer signs the release with a private key; users verify with the published
public key. Real-world: OpenBSD signify, minisign, `ssh-keygen -Y sign`, Solana transactions.

**Threat.** An attacker takes over the download mirror and swaps the release for malware.

**Primitive & guarantee.** An **Ed25519 digital signature** (private key signs, public key verifies) gives
**integrity + authenticity**. A plain SHA-256 checksum gives **integrity only** — anyone can recompute it.

**What the demo shows** (`app/case1_ed25519_release_signing.py`, output in `results/case1_output.txt`):
- Step 4 is the headline: the attacker swaps the release *and* recomputes the checksum. The checksum check passes,
  the signature check **fails** — forging the signature would need the private key.
- Step 6: the attacker's own signature is valid under *their* public key, not the developer's — so the public key
  must come from a trusted place, not the mirror.
- Step 7: signing the same file twice gives an identical signature. Ed25519 computes its nonce from
  `hash(private key, message)`, so a broken RNG can't make it reuse a nonce — the bug that breaks Case 2.

**What breaks if misused.** Trust collapses if the private key is stolen, or if users fetch the public key from an
untrusted source. The signature is only as trustworthy as the public key you check it against.

```
Step 4. Why not just a checksum? An attacker takes over the mirror
  checksum check:  OK
  signature check: FAIL
```

---

## Case 2 — ECDSA nonce reuse (the "big lie of ECDSA")

**Scenario.** A wallet or firmware signer has a broken random number generator and signs two different messages
with the **same** one-time nonce `k`. Curve: secp256k1 (Bitcoin / Ethereum).

**Threat.** Anyone who sees the two signatures can recover the private key and forge new signatures.

**Primitive & guarantee.** **ECDSA** gives **authenticity** — *if* `k` is fresh and secret every time. Its security
rests entirely on that.

**Real cases.** Sony PS3 (2010): constant `k`, firmware master key recovered. Android Bitcoin wallets (2013):
a `SecureRandom` bug repeated `k`, coins stolen.

**What the demo shows** (`app/case2_ecdsa_nonce_reuse.py`, output in `results/case2_output.txt`):
- Both signatures verify, and `r1 == r2` — the visible fingerprint of nonce reuse (`r` depends only on `k`).
- The attacker recovers `k`, then the private key `d`, from the public values alone.
- Proof: the recovered `d` equals the real one, and it signs a brand-new message that the victim's own public key
  accepts — full forgery.
- Fixes: a fresh random `k` each time, or **RFC 6979 deterministic ECDSA** (compute `k` from the key+message,
  like Ed25519). RFC 6979 is the real fix — no RNG to get wrong.

### How the nonce-reuse math works

ECDSA signs with `s = k⁻¹ · (z + r·d)  mod n`, where `z` = message hash, `d` = private key, `k` = nonce,
`n` = curve order. Two messages signed with the same `k` (so the same `r`):

```
s1 = k⁻¹ · (z1 + r·d)
s2 = k⁻¹ · (z2 + r·d)
```

Subtract — `r·d` cancels — and solve:

```
k = (z1 − z2) · (s1 − s2)⁻¹   mod n
d = (s1·k − z1) · r⁻¹          mod n
```

Two public signatures, two lines of algebra, private key recovered. (`x⁻¹` means the modular inverse,
`pow(x, -1, n)` in Python.)

---

## Part 3 — Testing restic (open-source backup tool)

restic is open-source encrypted backup software whose core feature is cryptography.

**Scenario.** You back up files. Later you need to know the backup wasn't silently corrupted or altered.

**Threat.** An attacker (or a failing disk) modifies the stored backup data.

**Primitives & guarantees.**
- **AES-256-CTR** encryption → **confidentiality** (a stolen backup drive is unreadable; a random IV per chunk
  keeps identical data from looking identical).
- **Poly1305 MAC** → **integrity + authenticity** (only the key-holder can produce a valid tag).
- **SHA-256 content-addressing** → each chunk is named by the hash of its contents; snapshot → trees → blobs
  referenced by hash form a **Merkle tree**, so a snapshot ID commits to all its data.
- Together this is an **AEAD** (same category as AES-GCM, built from AES-CTR + Poly1305).
- The random **master key** encrypts the data; it's stored encrypted under a key derived from your password via
  **scrypt**, so you can change the password without re-encrypting the data.

### Runbook (what I tested)

Run from the repo root. Full captured output in `results/restic_output.txt`.

```bash
export RESTIC_REPOSITORY=out/restic/repo
export RESTIC_PASSWORD=demo-password-not-a-secret        # demo only, never a real secret
mkdir -p out/restic/src

# 1. create the encrypted repo and back up some files (incl. a 2 MB file)
restic init
echo "my bank statements" > out/restic/src/notes.txt
head -c 2000000 /dev/urandom > out/restic/src/big.bin
restic backup out/restic/src

# 2. verify the healthy backup
restic check --read-data                                  # -> no errors were found

# 3. tamper: overwrite 16 bytes inside the largest (data) pack
PACK=$(ls -S out/restic/repo/data/*/* | head -1)
chmod u+w "$PACK"
printf 'XXXXXXXXXXXXXXXX' | dd of="$PACK" bs=1 seek=1000000 conv=notrunc

# 4. the result
restic check                                              # PASSES: only checks structure
restic check --read-data                                  # FAILS: "ciphertext verification failed"
restic restore latest --target out/restic/restore         # restores good files, REFUSES the corrupted one
```

Reset for a clean re-run: `chmod -R u+w out/restic && rm -rf out/restic`.

### Result

```
restic check              -> no errors were found              (exit 0)
restic check --read-data  -> pack ... ciphertext verification failed   (exit 1)
restic restore            -> ignoring error for big.bin ... Restored 4/5   (exit 1)
```

**Why plain `check` passes but `--read-data` fails.** Plain `check` verifies only the structure (trees and that
referenced packs exist); it doesn't re-read data contents. `--read-data` re-downloads every pack and recomputes the
MAC and hash — that's what catches the flipped bytes. (We corrupt the *largest* pack to be sure it's a data pack,
not a tree pack, which plain `check` would already read.)

**What breaks if misused.** Lose the password → the master key is unrecoverable and the data is gone. Reuse an IV
with the same key → confidentiality leaks (the same class of nonce-reuse bug as Case 2).

---

## Q&A

**Does a signature give confidentiality?** No — only integrity + authenticity. The release file is published in the
clear. Confidentiality needs encryption (that's what restic adds).

**Why did the checksum pass in Case 1 step 4 but the signature fail?** SHA-256 needs no key, so the attacker just
recomputed it. A valid signature needs the developer's private key, which the attacker doesn't have.

**Why must the public key come from a trusted place?** A signature only proves "the owner of *this* public key
signed it." If the attacker also replaces the public key (e.g. on the hacked mirror), their forgery verifies. The
key must come from somewhere the attacker can't touch.

**Is Ed25519 a hash?** No, it's a signature algorithm. It uses SHA-512 internally (to derive the secret and the
nonce), but its security comes from elliptic-curve math: `public = secret × base point`, which can't be reversed.

**Ed25519 vs ECDSA?** Both are elliptic-curve signatures. ECDSA takes its nonce from an RNG and leaks the key if the
nonce repeats; Ed25519 computes its nonce deterministically, so it can't.

**Why does Bitcoin use ECDSA, not Ed25519?** Timing: Bitcoin launched in 2009, Ed25519 appeared in 2011. Switching
would change the rules for the whole network. ECDSA is safe with RFC 6979; Bitcoin later added Schnorr (Taproot, 2021).

**Isn't a deterministic (repeatable) signature a weakness?** No. The nonce is computed from a *secret*, so it looks
random to everyone else and can't be predicted for new messages. Determinism is what makes nonce reuse impossible.

**What if the private key is stolen (Case 1)?** The attacker can sign as the developer; the demo doesn't defend
against that. Real mitigations: keep the key offline/in hardware, rotate and revoke keys, require multiple signers
(multisig), use transparency logs (Sigstore).

**restic: does it use AES-GCM?** No — it builds its own AEAD from AES-256-CTR + Poly1305 (encrypt-then-MAC). Same
guarantees as AES-GCM, different construction.

**MAC vs HMAC vs hash?** A hash is a keyless fingerprint (integrity). A MAC is a keyed fingerprint (integrity +
authenticity). HMAC is one way to build a MAC from a hash; restic uses Poly1305, not HMAC.

**Does Bitcoin enforce low-s?** Yes — ECDSA signatures have a "twin" (`s` and `n − s`), and Bitcoin standardizes on
low-s to prevent malleability. Our recovery works directly because python-ecdsa's raw encoder doesn't normalize; if
it did, you'd try both `s` and `n − s` and keep the `d` that matches the public key.

---

## Repo layout

```
app/       case1_ed25519_release_signing.py   case2_ecdsa_nonce_reuse.py
results/   captured output of each run
out/       generated files (gitignored)
```

Never commit keys or secrets. The only hand-written crypto is the Case 2 attack math — that's the point of the case.
