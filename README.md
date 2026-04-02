# Running Key Cipher

A Python implementation of the Running Key Cipher using **djb2 hashing** and an **LCG key stream generator**.

---

## How It Works

The cipher runs in three stages:

```
passphrase  ──►  djb2 hash  ──►  LCG key stream  ──►  encrypt / decrypt
```

### 1. djb2 Hash
Converts the passphrase into a single 32-bit integer (the seed).

```
hash = 5381
for each character:
    hash = (hash * 33) XOR charCode(character)
```

### 2. LCG Key Stream
Uses the seed to generate an infinite, non-repeating stream of pseudo-random bytes.

```
x(n+1) = (1664525 * x(n) + 1013904223) mod 2³²
```

This is what makes it a *running key* — the key never repeats, which defeats frequency and Kasiski analysis.

### 3. Cipher (letters only)
```
Encrypt:  C = (P + K) mod 26
Decrypt:  P = (C - K + 26) mod 26
```
Non-letter characters (spaces, punctuation) pass through unchanged.

---

## Usage

```bash
python running_key_cipher.py
```

You will be prompted for:

```
Mode (encrypt/decrypt): encrypt
Message: hello world
Key: theskyispink

Output: XQTTE BVFZV
```

To decrypt, use the exact same key:

```
Mode (encrypt/decrypt): decrypt
Message: XQTTE BVFZV
Key: theskyispink

Output: HELLO WORLD
```

---

## Files

| File | Description |
|------|-------------|
| `running_key_cipher.py` | Main cipher implementation |
| `README.md` | This file |

---

## Design Notes

- **Case-insensitive** — input is automatically uppercased before processing
- **Non-letters preserved** — spaces and punctuation are not enciphered
- **Deterministic** — the same key always produces the same key stream
- **djb2 is not cryptographically secure** — it is chosen for its transparency and auditability. The full pipeline (key → hash → stream → cipher) is readable in plain code. For real-world security, replace with a CSPRNG seeded via PBKDF2.
