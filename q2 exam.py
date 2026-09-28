"""
Python Security Toolkit
Module: ETTCS801 Cryptography and Network Security
Handles file encryption/decryption (AES-GCM) and integrity checks (SHA-256).
"""

import os
import sys
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Key handling: load from environment variable or external file
KEY_FILE = "secret.key"

def load_or_generate_key() -> bytes:
    """Loads key from secret.key or generates a new AES-256 key if missing."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = AESGCM.generate_key(bit_length=256)
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        print(f"[+] Generated new encryption key saved to '{KEY_FILE}' (Keep this outside repo!).")
        return key

def compute_sha256(file_path: str) -> str:
    """Calculates SHA-256 checksum of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        print(f"[-] Error: File '{file_path}' not found.")
        return ""
    except Exception as e:
        print(f"[-] Unexpected error reading '{file_path}': {e}")
        return ""

def encrypt_file(file_path: str, output_path: str, key: bytes) -> bool:
    """Encrypts file using AES-256-GCM."""
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Source file '{file_path}' does not exist.")

        with open(file_path, "rb") as f:
            plaintext = f.read()

        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        with open(output_path, "wb") as f:
            f.write(nonce + ciphertext)

        print(f"[+] File successfully encrypted to '{output_path}'.")
        return True
    except FileNotFoundError as e:
        print(f"[-] Input Error: {e}")
    except Exception as e:
        print(f"[-] Encryption failed: {e}")
    return False

def decrypt_file(encrypted_path: str, output_path: str, key: bytes) -> bool:
    """Decrypts AES-256-GCM encrypted file."""
    try:
        if not os.path.exists(encrypted_path):
            raise FileNotFoundError(f"Encrypted file '{encrypted_path}' does not exist.")

        with open(encrypted_path, "rb") as f:
            data = f.read()

        if len(data) < 12:
            raise ValueError("File is corrupted or invalid ciphertext format.")

        nonce = data[:12]
        ciphertext = data[12:]

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        with open(output_path, "wb") as f:
            f.write(plaintext)

        print(f"[+] File successfully decrypted to '{output_path}'.")
        return True
    except FileNotFoundError as e:
        print(f"[-] Input Error: {e}")
    except Exception as e:
        print(f"[-] Decryption failed (Key mismatch or tampered file): {e}")
    return False

if __name__ == "__main__":
    print("=== Cryptography & Security Toolkit ===")
    key = load_or_generate_key()

    sample_file = "sample_students.csv"
    encrypted_file = "sample_students.enc"
    decrypted_file = "sample_students_restored.csv"

    # Create dummy file for demo if absent
    if not os.path.exists(sample_file):
        with open(sample_file, "w") as f:
            f.write("ID,Name,Grade\n101,John Doe,A\n102,Jane Smith,B\n")
        print(f"[+] Created sample file '{sample_file}'.")

    # 1. Calculate Hash
    orig_hash = compute_sha256(sample_file)
    print(f"[*] Original File Hash (SHA-256): {orig_hash}")

    # 2. Encrypt
    encrypt_file(sample_file, encrypted_file, key)

    # 3. Decrypt
    decrypt_file(encrypted_file, decrypted_file, key)

    # 4. Verify Integrity
    restored_hash = compute_sha256(decrypted_file)
    print(f"[*] Restored File Hash (SHA-256): {restored_hash}")

    if orig_hash == restored_hash:
        print("[SUCCESS] Integrity Verified: The decrypted file matches the original.")
    else:
        print("[WARNING] Integrity Check Failed: Files do not match!")