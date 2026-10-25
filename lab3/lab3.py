"""Laboratorul 3, sarcina 3.1: cifrul Playfair pentru alfabetul romanesc."""

import sys
import unicodedata


ALPHABET = (
    "A", "Ă", "Â", "B", "C", "D", "E", "F", "G", "H", "I", "Î", "J", "K",
    "L", "M", "N", "O", "P", "Q", "R", "S", "Ș", "T", "Ț", "U", "V", "W",
    "X", "Y", "Z",
)
MIN_KEY_LENGTH = 7
PLAYFAIR_ROWS = 6
PLAYFAIR_COLUMNS = 5
# 31 de litere nu umplu o matrice dreptunghiulara, deci Q (cea mai rara litera
# in limba romana) este inlocuita cu K si raman 30 de litere = 6 x 5.
REPLACED_LETTER = "Q"
REPLACEMENT = "K"
MATRIX_ALPHABET = tuple(
    character for character in ALPHABET if character != REPLACED_LETTER
)
FILLER = "X"
ALTERNATE_FILLER = "Y"

CEDILLA_FIX = {"Ş": "Ș", "Ţ": "Ț"}
ALLOWED_HINT = "A-Z, a-z, Ă, Â, Î, Ș, Ț (ă, â, î, ș, ț) si spatii"


def normalize(value):
    """Return uppercase NFC text with Romanian cedillas normalized."""
    normalized = unicodedata.normalize("NFC", value).upper()
    return "".join(CEDILLA_FIX.get(character, character) for character in normalized)


def validate_text(raw):
    """Validate and compact a message or key, returning (text, invalid_character)."""
    text = normalize(raw).replace(" ", "")
    for character in text:
        if character not in ALPHABET:
            return None, character
    return text.replace(REPLACED_LETTER, REPLACEMENT), None


def unique_key(key):
    """Remove repeated letters from a Playfair key, preserving first occurrence."""
    return "".join(dict.fromkeys(key))


def build_playfair_matrix(key):
    """Build a 6x5 matrix containing every matrix alphabet character once."""
    key = unique_key(key)
    sequence = key + "".join(
        character for character in MATRIX_ALPHABET if character not in key
    )
    return [
        sequence[row * PLAYFAIR_COLUMNS:(row + 1) * PLAYFAIR_COLUMNS]
        for row in range(PLAYFAIR_ROWS)
    ]


def _filler_for(character):
    return ALTERNATE_FILLER if character == FILLER else FILLER


def prepare_playfair_text(text):
    """Split text into digraphs, separating repeated letters and padding the end."""
    pairs = []
    index = 0
    while index < len(text):
        first = text[index]
        second = text[index + 1] if index + 1 < len(text) else None
        if second is None or first == second:
            pairs.append(first + _filler_for(first))
            index += 1
        else:
            pairs.append(first + second)
            index += 2
    return "".join(pairs)


def _playfair_positions(matrix):
    return {
        character: (row, column)
        for row, line in enumerate(matrix)
        for column, character in enumerate(line)
    }


def playfair(text, key, decrypt=False):
    """Encrypt or decrypt a prepared Playfair message."""
    if len(text) % 2:
        raise ValueError("Textul Playfair trebuie sa contina un numar par de litere.")
    matrix = build_playfair_matrix(key)
    positions = _playfair_positions(matrix)
    result = []
    step = -1 if decrypt else 1

    for index in range(0, len(text), 2):
        first, second = text[index:index + 2]
        row1, column1 = positions[first]
        row2, column2 = positions[second]
        if row1 == row2:
            result.extend((
                matrix[row1][(column1 + step) % PLAYFAIR_COLUMNS],
                matrix[row2][(column2 + step) % PLAYFAIR_COLUMNS],
            ))
        elif column1 == column2:
            result.extend((
                matrix[(row1 + step) % PLAYFAIR_ROWS][column1],
                matrix[(row2 + step) % PLAYFAIR_ROWS][column2],
            ))
        else:
            result.extend((matrix[row1][column2], matrix[row2][column1]))
    return "".join(result)


def _in_pairs(text):
    return " ".join(text[index:index + 2] for index in range(0, len(text), 2))


def _read_key():
    while True:
        key, invalid = validate_text(input(f"Cheia (minimum {MIN_KEY_LENGTH} litere): "))
        if invalid is not None:
            print(f"Caracter invalid: {invalid!r}. Folositi doar: {ALLOWED_HINT}.")
        elif len(key) < MIN_KEY_LENGTH:
            print(f"Cheia trebuie sa aiba cel putin {MIN_KEY_LENGTH} litere.")
        else:
            return key


def _read_message(prompt, decrypt=False):
    while True:
        message, invalid = validate_text(input(prompt))
        if invalid is not None:
            print(f"Caracter invalid: {invalid!r}. Folositi doar: {ALLOWED_HINT}.")
        elif not message:
            print("Textul nu poate fi gol.")
        elif decrypt and len(message) % 2:
            print("Criptograma trebuie sa aiba un numar par de litere.")
        else:
            return message


def _show_matrix(matrix):
    print("Matricea Playfair:")
    for row in matrix:
        print(" ".join(row))


def _run_playfair(decrypt=False):
    key = _read_key()
    message = _read_message("Criptograma: " if decrypt else "Mesajul: ", decrypt)
    _show_matrix(build_playfair_matrix(key))
    if decrypt:
        result = playfair(message, key, decrypt=True)
        print("Mesaj decriptat (pe perechi):", _in_pairs(result))
        print("Mesaj decriptat:", result)
        print(f"Eliminati manual literele {FILLER}/{ALTERNATE_FILLER} adaugate "
              "si puneti spatiile intre cuvinte.")
    else:
        prepared = prepare_playfair_text(message)
        print("Mesaj pregatit:", _in_pairs(prepared))
        print("Criptograma:", playfair(prepared, key))


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    while True:
        print("\n=== Cifrul Playfair (alfabetul romanesc) ===")
        print("1. Criptare")
        print("2. Decriptare")
        print("0. Iesire")
        choice = input("Alege (0-2): ").strip()
        if choice == "1":
            _run_playfair()
        elif choice == "2":
            _run_playfair(decrypt=True)
        elif choice == "0":
            return
        else:
            print("Optiune invalida. Alegeti un numar intre 0 si 2.")


if __name__ == "__main__":
    main()
