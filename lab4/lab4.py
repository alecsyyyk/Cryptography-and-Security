"""Laboratorul 4, sarcina 2.7: aplicarea cutiilor S din algoritmul DES."""

import random
import sys


INPUT_BITS = 48
BLOCK_COUNT = 8
BLOCK_BITS = 6
OUTPUT_BITS = 4

# Cutiile S1-S8 din standardul FIPS 46-3: 4 randuri x 16 coloane fiecare.
S_BOXES = (
    (
        (14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7),
        (0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8),
        (4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0),
        (15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13),
    ),
    (
        (15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10),
        (3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5),
        (0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15),
        (13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9),
    ),
    (
        (10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8),
        (13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1),
        (13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7),
        (1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12),
    ),
    (
        (7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15),
        (13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9),
        (10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4),
        (3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14),
    ),
    (
        (2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9),
        (14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6),
        (4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14),
        (11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3),
    ),
    (
        (12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11),
        (10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8),
        (9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6),
        (4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13),
    ),
    (
        (4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1),
        (13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6),
        (1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2),
        (6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12),
    ),
    (
        (13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7),
        (1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2),
        (7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8),
        (2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11),
    ),
)


def validate_bits(raw):
    """Remove spaces and check the input, returning (bits, error_message)."""
    bits = raw.replace(" ", "")
    for character in bits:
        if character not in "01":
            return None, f"Caracter invalid: {character!r}. Folositi doar 0 si 1."
    if len(bits) != INPUT_BITS:
        return None, (f"Trebuie exact {INPUT_BITS} de biti "
                      f"(ati introdus {len(bits)}).")
    return bits, None


def random_bits():
    """Generate a random 48-bit string."""
    return "".join(random.choice("01") for _ in range(INPUT_BITS))


def split_blocks(bits):
    """Split 48 bits into the eight 6-bit blocks B1..B8."""
    return [bits[index:index + BLOCK_BITS] for index in range(0, len(bits), BLOCK_BITS)]


def sbox_lookup(box_number, block):
    """Apply S-box number box_number (1-8) to a 6-bit block.

    Returns (row, column, value, output_bits).
    """
    row = int(block[0] + block[-1], 2)
    column = int(block[1:-1], 2)
    value = S_BOXES[box_number - 1][row][column]
    return row, column, value, format(value, f"0{OUTPUT_BITS}b")


def apply_sboxes(bits):
    """Return S1(B1)S2(B2)...S8(B8) as a 32-bit string."""
    return "".join(
        sbox_lookup(number, block)[3]
        for number, block in enumerate(split_blocks(bits), start=1)
    )


def _in_groups(bits, size):
    return " ".join(bits[index:index + size] for index in range(0, len(bits), size))


def _read_bits():
    while True:
        bits, error = validate_bits(input(f"B1B2...B8 ({INPUT_BITS} de biti): "))
        if error is not None:
            print(error)
        else:
            return bits


def _show_sbox(box_number, selected_row, selected_column):
    print(f"Tabelul S{box_number} (valoarea aleasa este intre [ ]):")
    print("       " + " ".join(f"{column:>4}" for column in range(16)))
    for row, line in enumerate(S_BOXES[box_number - 1]):
        cells = []
        for column, value in enumerate(line):
            if row == selected_row and column == selected_column:
                cells.append(f"[{value:>2}]")
            else:
                cells.append(f"{value:>4}")
        print(f"  r{row}:  " + " ".join(cells))


def _run_sboxes(bits):
    print("\nIntrarea (48 de biti):", _in_groups(bits, BLOCK_BITS))
    for number, block in enumerate(split_blocks(bits), start=1):
        row, column, value, output = sbox_lookup(number, block)
        print(f"\n--- B{number} = {block} ---")
        print(f"Randul:  primul si ultimul bit {block[0]}{block[-1]} -> {row}")
        print(f"Coloana: bitii din mijloc {block[1:-1]} -> {column}")
        _show_sbox(number, row, column)
        print(f"S{number}(B{number}) = S{number}[{row}][{column}] = {value} -> {output}")

    result = apply_sboxes(bits)
    print("\nS1(B1)S2(B2)...S8(B8) (32 de biti):", _in_groups(result, OUTPUT_BITS))
    print("In hexazecimal:", format(int(result, 2), "08X"))


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    while True:
        print("\n=== DES: cutiile S (sarcina 2.7) ===")
        print("1. Introduc B1B2...B8")
        print("2. Generez B1B2...B8 aleatoriu")
        print("0. Iesire")
        choice = input("Alege (0-2): ").strip()
        if choice == "1":
            _run_sboxes(_read_bits())
        elif choice == "2":
            _run_sboxes(random_bits())
        elif choice == "0":
            return
        else:
            print("Optiune invalida. Alegeti un numar intre 0 si 2.")


if __name__ == "__main__":
    main()
