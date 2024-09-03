import os
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AES_KEY_SIZE = 32  # AES-256 uses 32 bytes key
SALT_SIZE = 16     # Size of the salt
NONCE_SIZE = 12    # Size of the nonce for AESGCM
ITERATIONS = 100000  # Number of iterations for PBKDF2

def generate_salt():
    return os.urandom(SALT_SIZE)

def derive_key_from_passphrase(passphrase: str, salt: bytes, length: int):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

def hash_passphrase(passphrase: str):
    return hashlib.sha256(passphrase.encode()).digest()

def encrypt_file_inplace(input_file: str, passphrase: str):
    dek_salt = generate_salt()
    dek = os.urandom(AES_KEY_SIZE)
    kek_salt = generate_salt()
    kek = derive_key_from_passphrase(passphrase, kek_salt, AES_KEY_SIZE)

    aesgcm = AESGCM(kek)
    dek_nonce = os.urandom(NONCE_SIZE)
    encrypted_dek = aesgcm.encrypt(dek_nonce, dek, None)

    file_nonce = os.urandom(NONCE_SIZE)
    with open(input_file, 'rb') as f:
        data = f.read()
    aesgcm = AESGCM(dek)
    ciphertext = aesgcm.encrypt(file_nonce, data, None)

    passphrase_hash = hash_passphrase(passphrase)

    with open(input_file, 'wb') as f:
        f.write(dek_salt + kek_salt + dek_nonce + encrypted_dek + passphrase_hash + file_nonce + ciphertext)

def decrypt_file_inplace(input_file: str, passphrase: str):
    try:
        with open(input_file, 'rb') as f:
            dek_salt = f.read(SALT_SIZE)
            kek_salt = f.read(SALT_SIZE)
            dek_nonce = f.read(NONCE_SIZE)
            encrypted_dek = f.read(AES_KEY_SIZE + 16)
            stored_passphrase_hash = f.read(32)
            file_nonce = f.read(NONCE_SIZE)
            ciphertext = f.read()

        provided_passphrase_hash = hash_passphrase(passphrase)
        if provided_passphrase_hash != stored_passphrase_hash:
            raise ValueError("Passphrase does not match.")

        kek = derive_key_from_passphrase(passphrase, kek_salt, AES_KEY_SIZE)

        aesgcm = AESGCM(kek)
        dek = aesgcm.decrypt(dek_nonce, encrypted_dek, None)

        aesgcm = AESGCM(dek)
        plaintext = aesgcm.decrypt(file_nonce, ciphertext, None)

        with open(input_file, 'wb') as f:
            f.write(plaintext)

    except Exception as e:
        print("Decryption failed:", str(e))
        raise
