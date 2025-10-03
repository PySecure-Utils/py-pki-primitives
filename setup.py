# setup.py

from setuptools import setup, find_packages

setup(
    name="pki-primitives",
    version="1.0.2",  # Bump the version number to ensure pip sees a change
    author="Core Systems Team",
    description="Provides low-level primitives for PKI operations.",
    packages=find_packages(where="src"),
    package_dir={"": "src"},            
    package_data={'pki_primitives': ['*.json']},
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=42.0",
    ],
)