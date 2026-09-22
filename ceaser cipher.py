def encrypt(text: str, shift: int) -> str:
    result = ""
    for char in text:
        if char.isupper():
            result += chr((ord(char) - 65 + shift) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) - 97 + shift) % 26 + 97)
        else:
            result += char
    return result


def decrypt(cipher_text: str, shift: int) -> str:
    result = ""
    for char in cipher_text:
        if char.isupper():
            result += chr((ord(char) - 65 - shift) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) - 97 - shift) % 26 + 97)
        else:
            result += char
    return result


def main():
    print("=" * 45)
    print("  DecodeLabs - Caesar Cipher Tool")
    print("=" * 45)

    plaintext = input("Enter the text to encrypt: ")

    while True:
        try:
            shift = int(input("Enter the shift key (e.g. 3): "))
            break
        except ValueError:
            print("Please enter a valid whole number for the shift key.")

    encrypted_text = encrypt(plaintext, shift)
    decrypted_text = decrypt(encrypted_text, shift)

    print("\n--- Results ---")
    print(f"Original Text : {plaintext}")
    print(f"Encrypted Text: {encrypted_text}")
    print(f"Decrypted Text: {decrypted_text}")

    if decrypted_text == plaintext:
        print("\n[OK] Decryption successful — matches original text.")
    else:
        print("\n[ERROR] Decryption mismatch — check the logic.")


if __name__ == "__main__":
    main()