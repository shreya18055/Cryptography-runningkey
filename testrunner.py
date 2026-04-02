import sys
from Runningkey import running_key_cipher, djb2, make_lcg

# ─────────────────────────────────────────────
#  TEST HELPERS
# ─────────────────────────────────────────────
passed = 0
failed = 0

def check(description: str, got, expected):
    global passed, failed
    if got == expected:
        print(f"  PASS  {description}")
        passed += 1
    else:
        print(f"  FAIL  {description}")
        print(f"          expected : {expected}")
        print(f"          got      : {got}")
        failed += 1


def section(title: str):
    print(f"\n{title}")
    print("─" * 50)


# ─────────────────────────────────────────────
#  1. djb2 HASH TESTS
#     Same input must always produce same output.
#     Different inputs must produce different hashes.
# ─────────────────────────────────────────────
section("1. djb2 Hash")

check("empty string returns seed 5381",
      djb2(""), 5381)

check("same input always gives same hash",
      djb2("hello"), djb2("hello"))

check("different inputs give different hashes",
      djb2("hello") != djb2("world"), True)

check("output is 32-bit unsigned (0 to 2^32 - 1)",
      0 <= djb2("theskyispink") <= 0xFFFFFFFF, True)

check("single character hashes correctly",
      djb2("a"), ((5381 << 5) + 5381 ^ ord('a')) & 0xFFFFFFFF)


# ─────────────────────────────────────────────
#  2. LCG KEY STREAM TESTS
#     Same seed must produce same sequence.
#     Output must stay within byte range.
# ─────────────────────────────────────────────
section("2. LCG Key Stream")

gen1 = make_lcg(12345)
gen2 = make_lcg(12345)
check("same seed produces same first byte",
      gen1(), gen2())

check("same seed produces same second byte",
      gen1(), gen2())

gen3 = make_lcg(99999)
check("different seeds produce different bytes",
      make_lcg(11111)() != make_lcg(99999)(), True)

gen4 = make_lcg(42)
check("output is always a valid byte (0–255)",
      all(0 <= gen4() <= 255 for _ in range(1000)), True)


# ─────────────────────────────────────────────
#  3. ENCRYPT / DECRYPT ROUNDTRIP TESTS
#     Decrypt(Encrypt(text, key), key) must equal
#     the original text (uppercased).
# ─────────────────────────────────────────────
section("3. Encrypt / Decrypt Roundtrip")

def roundtrip(plaintext, key):
    encrypted = running_key_cipher(plaintext, key, 'encrypt')
    decrypted = running_key_cipher(encrypted, key, 'decrypt')
    return decrypted == plaintext.upper()

check("roundtrip: simple word",
      roundtrip("HELLO", "mykey"), True)

check("roundtrip: known case — SHREYA / theskyispink",
      running_key_cipher("shreya", "theskyispink", "encrypt"), "OIYLCU")

check("roundtrip: decrypt known ciphertext back to plaintext",
      running_key_cipher("OIYLCU", "theskyispink", "decrypt"), "SHREYA")

check("roundtrip: full sentence",
      roundtrip("THE QUICK BROWN FOX", "secretpassphrase"), True)

check("roundtrip: lowercase input treated same as uppercase",
      running_key_cipher("hello", "key", "encrypt"),
      running_key_cipher("HELLO", "key", "encrypt"))


# ─────────────────────────────────────────────
#  4. NON-LETTER PASSTHROUGH TESTS
#     Spaces, digits, punctuation must be unchanged.
# ─────────────────────────────────────────────
section("4. Non-Letter Passthrough")

encrypted = running_key_cipher("HELLO WORLD", "key", "encrypt")
check("space preserved in position",
      encrypted[5], " ")

encrypted2 = running_key_cipher("HI, THERE!", "key", "encrypt")
check("comma preserved",
      encrypted2[2], ",")

check("exclamation preserved",
      encrypted2[-1], "!")

check("digits pass through unchanged",
      running_key_cipher("ABC123", "key", "encrypt")[3:], "123")


# ─────────────────────────────────────────────
#  5. EDGE CASE TESTS
# ─────────────────────────────────────────────
section("5. Edge Cases")

check("empty string returns empty string",
      running_key_cipher("", "anykey", "encrypt"), "")

check("only spaces returns only spaces",
      running_key_cipher("   ", "anykey", "encrypt"), "   ")

check("different keys produce different ciphertexts",
      running_key_cipher("HELLO", "key1", "encrypt") !=
      running_key_cipher("HELLO", "key2", "encrypt"), True)

check("single character encrypts and decrypts",
      roundtrip("A", "z"), True)

try:
    running_key_cipher("hello", "key", "badmode")
    check("invalid mode raises ValueError", False, True)
except ValueError:
    check("invalid mode raises ValueError", True, True)


# ─────────────────────────────────────────────
#  SUMMARY
# ─────────────────────────────────────────────
total = passed + failed
print(f"\n{'─' * 50}")
print(f"  Results: {passed}/{total} passed", end="")
print(" ✓" if failed == 0 else f"  ({failed} failed)")
print(f"{'─' * 50}\n")

sys.exit(0 if failed == 0 else 1)