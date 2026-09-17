import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_LENGTH = 16
NONCE_LENGTH = 12
KEY_LENGTH = 32


def derive_encryption_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from the authenticated master password."""
    kdf = Scrypt(
        salt=salt,
        length=KEY_LENGTH,
        n=2**14,
        r=8,
        p=1,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_json(data: dict, key: bytes) -> str:
    """Encrypt a JSON object with AES-256-GCM and a fresh random nonce."""
    nonce = os.urandom(NONCE_LENGTH)
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_json(token: str, key: bytes) -> dict:
    """Decrypt and authenticate an encrypted JSON object."""
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
        nonce, ciphertext = raw[:NONCE_LENGTH], raw[NONCE_LENGTH:]
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Encrypted data is invalid or the key is incorrect.") from exc
