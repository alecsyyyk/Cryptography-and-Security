import unicodedata
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ALPHABET = [
    "A", "Ă", "Â", "B", "C", "D", "E", "F", "G", "H", "I", "Î", "J", "K", "L", "M",
    "N", "O", "P", "Q", "R", "S", "Ș", "T", "Ț", "U", "V", "W", "X", "Y", "Z",
]
N = len(ALPHABET)
MIN_KEYWORD_LEN = 7

CEDILLA_FIX = {"\u015e": "Ș", "\u0162": "Ț"}


def normalize(text):
    text = unicodedata.normalize("NFC", text).upper()
    return "".join(CEDILLA_FIX.get(ch, ch) for ch in text)


def clean_text(raw):
    text = normalize(raw).replace(" ", "")
    for ch in text:
        if ch not in ALPHABET:
            return None, ch
    return text, None


def read_key():
    while True:
        raw = input(f"Key k (integer between 1 and {N - 1}): ").strip()
        try:
            k = int(raw)
        except ValueError:
            print(f"  Error: '{raw}' is not an integer. "
                  f"Allowed values: 1 ... {N - 1}.")
            continue
        if 1 <= k <= N - 1:
            return k
        print(f"  Error: key {k} is out of range. "
              f"Allowed values: 1 ... {N - 1}.")


def read_text(prompt):
    while True:
        raw = input(prompt)
        text, bad = clean_text(raw)
        if bad is not None:
            print(f"  Error: character '{bad}' is not part of the Romanian "
                f"alphabet. Only letters (A-Z, Ă, Â, Î, Ș, Ț) and spaces "
                f"are allowed.")
            continue
        if not text:
            print("  Error: text is empty.")
            continue
        return text


def read_keyword():
    while True:
        raw = input(f"Keyword (at least {MIN_KEYWORD_LEN} letters): ")
        word, bad = clean_text(raw)
        if bad is not None:
            print(f"  Error: character '{bad}' is not a letter in the Romanian "
                f"alphabet (spaces are not allowed in the key).")
            continue
        if " " in raw.strip():
            print("  Error: the keyword must not contain spaces.")
            continue
        if len(word) < MIN_KEYWORD_LEN:
            print(f"  Error: the keyword has {len(word)} letters; "
                f"it must have at least {MIN_KEYWORD_LEN}.")
            continue
        return word


def build_permuted_alphabet(keyword):
    result = []
    seen = set()
    for ch in keyword:
        if ch in seen:
            continue
        result.append(ch)
        seen.add(ch)
    for ch in ALPHABET:
        if ch in seen:
            continue
        result.append(ch)
        seen.add(ch)
    return result


def caesar(text, k, alphabet, decrypt=False):
    position = {letter: i for i, letter in enumerate(alphabet)}
    shift = -k if decrypt else k
    alphabet_size = len(alphabet)
    return "".join(alphabet[(position[ch] + shift) % alphabet_size] for ch in text)


def simple_encrypt():
    print("\n--- Simple Caesar Cipher (Encrypt) ---")
    k = read_key()
    text = read_text("Plaintext: ")
    print("Encrypted text:", caesar(text, k, ALPHABET))


def simple_decrypt():
    print("\n--- Simple Caesar Cipher (Decrypt) ---")
    k = read_key()
    text = read_text("Ciphertext: ")
    print("Decrypted text:", caesar(text, k, ALPHABET, True))


def simple_analyze():
    print("\n--- Simple Caesar Cipher (Analyze) ---")
    text = read_text("Ciphertext: ")
    for k in range(1, N):
        print(f"Key {k:2}: {caesar(text, k, ALPHABET, True)}")


def keyword_encrypt():
    print("\n--- Keyword Caesar Cipher (Encrypt) ---")
    k = read_key()
    keyword = read_keyword()
    alphabet = build_permuted_alphabet(keyword)
    print("Permuted alphabet:", " ".join(alphabet))
    text = read_text("Plaintext: ")
    print("Encrypted text:", caesar(text, k, alphabet))


def keyword_decrypt():
    print("\n--- Keyword Caesar Cipher (Decrypt) ---")
    k = read_key()
    keyword = read_keyword()
    alphabet = build_permuted_alphabet(keyword)
    print("Permuted alphabet:", " ".join(alphabet))
    text = read_text("Ciphertext: ")
    print("Decrypted text:", caesar(text, k, alphabet, True))


def keyword_analyze():
    print("\n--- Keyword Caesar Cipher (Analyze) ---")
    keyword = read_keyword()
    alphabet = build_permuted_alphabet(keyword)
    print("Permuted alphabet:", " ".join(alphabet))
    text = read_text("Ciphertext: ")
    for k in range(1, N):
        print(f"Key {k:2}: {caesar(text, k, alphabet, True)}")


def show_examples():
    plaintext = clean_text("CIFRUL CEZAR")[0]
    key = 3
    keyword = "CRYPTOGRAPHY"
    alphabet = build_permuted_alphabet(keyword)
    encrypted = caesar(plaintext, key, ALPHABET)
    decrypted = caesar(encrypted, key, ALPHABET, True)
    permuted_encrypted = caesar(plaintext, key, alphabet)
    permuted_decrypted = caesar(permuted_encrypted, key, alphabet, True)

    print("\n=== Examples ===")
    print("Plaintext:", plaintext)
    print("Key:", key)
    print("Caesar encrypted:", encrypted)
    print("Caesar decrypted:", decrypted)
    print("Keyword:", keyword)
    print("Permuted alphabet:", " ".join(alphabet))
    print("Two-key encrypted:", permuted_encrypted)
    print("Two-key decrypted:", permuted_decrypted)


def main():
    while True:
        print("\n=== Caesar Cipher Menu ===")
        print("1. Simple Caesar Cipher (Encrypt)")
        print("2. Simple Caesar Cipher (Decrypt)")
        print("3. Simple Caesar Cipher (Analyze)")
        print("4. Keyword Caesar Cipher (Encrypt)")
        print("5. Keyword Caesar Cipher (Decrypt)")
        print("6. Keyword Caesar Cipher (Analyze)")
        print("7. Show Examples")
        print("0. Exit")
        choice = input("Choose (0-7): ").strip()
        if choice == "1":
            simple_encrypt()
        elif choice == "2":
            simple_decrypt()
        elif choice == "3":
            simple_analyze()
        elif choice == "4":
            keyword_encrypt()
        elif choice == "5":
            keyword_decrypt()
        elif choice == "6":
            keyword_analyze()
        elif choice == "7":
            show_examples()
        elif choice == "0":
            break
        else:
            print("  Error: choose a number from 0 to 7.")


if __name__ == "__main__":
    main()