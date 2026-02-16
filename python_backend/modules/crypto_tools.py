"""
Cryptography Tools Module
Real encryption/decryption, hashing, HMAC, password generation, and JWT inspection.
"""

import base64
import hashlib
import hmac
import json
import math
import secrets
import string
import urllib.parse
from typing import Any, Dict, Optional

import bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptoTools:
    """Cryptographic operations handler."""

    def __init__(self):
        self.supported_ciphers = ["AES-256", "RSA", "Base64", "URL", "Hex", "ROT13"]
        self.supported_hashes = [
            "MD5",
            "SHA-1",
            "SHA-256",
            "SHA-512",
            "SHA3-256",
            "SHA3-512",
            "BLAKE2B",
            "bcrypt",
        ]

    def encrypt(self, algorithm: str, data: str, key: Optional[str] = None) -> str:
        """Encrypt/encode data using the selected algorithm."""
        algo = algorithm.strip().upper()
        if algo == "BASE64":
            return base64.b64encode(data.encode("utf-8")).decode("utf-8")
        if algo == "URL":
            return urllib.parse.quote(data, safe="")
        if algo == "HEX":
            return data.encode("utf-8").hex()
        if algo == "ROT13":
            return data.translate(
                str.maketrans(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
                )
            )
        if algo == "AES-256":
            if not key:
                raise ValueError("AES-256 requires a passphrase key.")
            return self._aes_encrypt(data, key)
        if algo == "RSA":
            if not key:
                raise ValueError("RSA encryption requires a PEM public key.")
            return self._rsa_encrypt(data, key)
        raise ValueError(f"Unsupported encryption algorithm: {algorithm}")

    def decrypt(self, algorithm: str, data: str, key: Optional[str] = None) -> str:
        """Decrypt/decode data using the selected algorithm."""
        algo = algorithm.strip().upper()
        try:
            if algo == "BASE64":
                return base64.b64decode(data.encode("utf-8"), validate=True).decode("utf-8")
            if algo == "URL":
                return urllib.parse.unquote(data)
            if algo == "HEX":
                return bytes.fromhex(data).decode("utf-8")
            if algo == "ROT13":
                return self.encrypt("ROT13", data)
            if algo == "AES-256":
                if not key:
                    raise ValueError("AES-256 requires a passphrase key.")
                return self._aes_decrypt(data, key)
            if algo == "RSA":
                if not key:
                    raise ValueError("RSA decryption requires a PEM private key.")
                return self._rsa_decrypt(data, key)
            raise ValueError(f"Unsupported decryption algorithm: {algorithm}")
        except Exception as exc:
            raise ValueError(f"Decryption failed: {exc}") from exc

    def hash(self, algorithm: str, data: str) -> str:
        """Hash data using the selected algorithm."""
        algo = algorithm.strip().upper()
        raw = data.encode("utf-8")

        if algo == "BCRYPT":
            return bcrypt.hashpw(raw, bcrypt.gensalt(rounds=12)).decode("utf-8")

        hash_map = {
            "MD5": hashlib.md5,
            "SHA-1": hashlib.sha1,
            "SHA-256": hashlib.sha256,
            "SHA-512": hashlib.sha512,
            "SHA3-256": hashlib.sha3_256,
            "SHA3-512": hashlib.sha3_512,
            "BLAKE2B": hashlib.blake2b,
        }
        if algo not in hash_map:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        return hash_map[algo](raw).hexdigest()

    def generate_password(
        self,
        length: int = 16,
        uppercase: bool = True,
        lowercase: bool = True,
        digits: bool = True,
        special: bool = True,
    ) -> Dict[str, Any]:
        """Generate secure password and estimate entropy."""
        if length < 4 or length > 256:
            raise ValueError("Password length must be between 4 and 256.")

        groups = []
        if uppercase:
            groups.append(string.ascii_uppercase)
        if lowercase:
            groups.append(string.ascii_lowercase)
        if digits:
            groups.append(string.digits)
        if special:
            groups.append("!@#$%^&*()_+-=[]{}|;:,.<>?")

        if not groups:
            raise ValueError("At least one character group must be selected.")

        alphabet = "".join(groups)
        password_chars = [secrets.choice(group) for group in groups]
        password_chars.extend(secrets.choice(alphabet) for _ in range(length - len(password_chars)))
        secrets.SystemRandom().shuffle(password_chars)
        password = "".join(password_chars)

        entropy = round(length * math.log2(len(alphabet)), 2)
        if entropy < 50:
            strength = "weak"
        elif entropy < 80:
            strength = "moderate"
        elif entropy < 120:
            strength = "strong"
        else:
            strength = "very strong"

        return {
            "password": password,
            "length": length,
            "entropy": entropy,
            "strength": strength,
            "alphabet_size": len(alphabet),
        }

    def hmac_sign(self, algorithm: str, data: str, key: str) -> str:
        """Generate HMAC signature using the selected digest."""
        if not key:
            raise ValueError("HMAC key is required.")
        algo = algorithm.strip().lower().replace("-", "")
        digest_map = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512,
            "sha3256": hashlib.sha3_256,
            "sha3512": hashlib.sha3_512,
            "blake2b": hashlib.blake2b,
        }
        if algo not in digest_map:
            raise ValueError(f"Unsupported HMAC algorithm: {algorithm}")
        return hmac.new(key.encode("utf-8"), data.encode("utf-8"), digest_map[algo]).hexdigest()

    def jwt_decode(self, token: str) -> Dict[str, Any]:
        """Decode JWT token without signature verification."""
        parts = token.split(".")
        if len(parts) != 3:
            return {"valid_format": False, "error": "Invalid JWT format. Expected 3 segments."}

        try:
            header = json.loads(self._decode_base64url(parts[0]))
            payload = json.loads(self._decode_base64url(parts[1]))
            return {
                "valid_format": True,
                "header": header,
                "payload": payload,
                "signature": parts[2],
            }
        except Exception as exc:
            return {"valid_format": False, "error": str(exc)}

    def generate_rsa_keypair(self, key_size: int = 2048) -> Dict[str, Any]:
        """Generate RSA private/public PEM keypair."""
        if key_size not in (2048, 3072, 4096):
            raise ValueError("RSA key size must be one of: 2048, 3072, 4096.")

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        return {
            "algorithm": "RSA",
            "key_size": key_size,
            "private_key_pem": private_pem,
            "public_key_pem": public_pem,
        }

    def _decode_base64url(self, value: str) -> str:
        padding_len = (4 - len(value) % 4) % 4
        padded = value + ("=" * padding_len)
        return base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8")

    def _derive_aes_key(self, passphrase: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200000,
            backend=default_backend(),
        )
        return kdf.derive(passphrase.encode("utf-8"))

    def _aes_encrypt(self, data: str, passphrase: str) -> str:
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        key = self._derive_aes_key(passphrase, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode("utf-8")) + encryptor.finalize()

        payload = {
            "v": 1,
            "alg": "AES-256-GCM",
            "salt": base64.b64encode(salt).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "tag": base64.b64encode(encryptor.tag).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        }
        return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")

    def _aes_decrypt(self, encoded_payload: str, passphrase: str) -> str:
        payload_json = base64.b64decode(encoded_payload.encode("utf-8")).decode("utf-8")
        payload = json.loads(payload_json)

        if payload.get("alg") != "AES-256-GCM":
            raise ValueError("Unsupported AES payload format.")

        salt = base64.b64decode(payload["salt"].encode("utf-8"))
        nonce = base64.b64decode(payload["nonce"].encode("utf-8"))
        tag = base64.b64decode(payload["tag"].encode("utf-8"))
        ciphertext = base64.b64decode(payload["ciphertext"].encode("utf-8"))
        key = self._derive_aes_key(passphrase, salt)

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode("utf-8")

    def _rsa_encrypt(self, data: str, public_key_pem: str) -> str:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8"),
            backend=default_backend(),
        )
        ciphertext = public_key.encrypt(
            data.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return base64.b64encode(ciphertext).decode("utf-8")

    def _rsa_decrypt(self, data: str, private_key_pem: str) -> str:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None,
            backend=default_backend(),
        )
        plaintext = private_key.decrypt(
            base64.b64decode(data.encode("utf-8")),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return plaintext.decode("utf-8")
