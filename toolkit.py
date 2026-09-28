import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_FILE = "secret.key"

def load_or_generate_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = AESGCM.generate_key(bit_length=256)
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        print(f"[+] Generated new encryption key in '{KEY_FILE}'.")
        return key

def compute_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def encrypt_file(file_path, output_path, key):
    with open(file_path, "rb") as f:
        plaintext = f.read()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    with open(output_path, "wb") as f:
        f.write(nonce + ciphertext)
    print(f"[+] File encrypted to '{output_path}'.")

def decrypt_file(encrypted_path, output_path, key):
    with open(encrypted_path, "rb") as f:
        data = f.read()
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    with open(output_path, "wb") as f:
        f.write(plaintext)
    print(f"[+] File decrypted to '{output_path}'.")

if __name__ == "__main__":
    print("=== Cryptography & Security Toolkit ===")
    key = load_or_generate_key()

    sample_file = "sample_students.csv"
    encrypted_file = "sample_students.enc"
    decrypted_file = "sample_students_restored.csv"

    if not os.path.exists(sample_file):
        with open(sample_file, "w") as f:
            f.write("ID,Name,Grade\n101,John Doe,A\n102,Jane Smith,B\n")
        print(f"[+] Created sample file '{sample_file}'.")

    orig_hash = compute_sha256(sample_file)
    print(f"[*] Original Hash: {orig_hash}")

    encrypt_file(sample_file, encrypted_file, key)
    decrypt_file(encrypted_file, decrypted_file, key)

    restored_hash = compute_sha256(decrypted_file)
    print(f"[*] Restored Hash: {restored_hash}")

    if orig_hash == restored_hash:
        print("[SUCCESS] Integrity Verified: Hashes match!")
    else:
        print("[WARNING] Integrity Check Failed!")