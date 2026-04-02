
def djb2(text: str) -> int:
    hash_val = 5381
    for char in text:
        hash_val = ((hash_val << 5) + hash_val) ^ ord(char)
        hash_val &= 0xFFFFFFFF 
    return hash_val


def make_lcg(seed: int):
    A, C, M = 1664525, 1013904223, 2**32
    state = seed

    def next_byte() -> int:
        nonlocal state
        state = (A * state + C) % M
        return (state >> 16) & 0xFF  

    return next_byte



def running_key_cipher(text: str, passphrase: str, mode: str) -> str:
    seed = djb2(passphrase)
    next_byte = make_lcg(seed)

    result = []
    for char in text.upper():
        if not char.isalpha():
            result.append(char) 
            continue

        p = ord(char) - ord('A')
        k = next_byte() % 26   

        if mode == 'encrypt':
            c = (p + k) % 26
        else:
            c = (p - k + 26) % 26

        result.append(chr(ord('A') + c))

    return ''.join(result)



if __name__ == "__main__":
    mode       = input("Mode (encrypt/decrypt): ").strip().lower()
    message    = input("Message: ").strip()
    passphrase = input("Key: ").strip()

    output = running_key_cipher(message, passphrase, mode)
    print(f"\nOutput: {output}")

