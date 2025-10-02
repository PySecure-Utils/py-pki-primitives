# setup.py

from setuptools import setup, find_packages

setup(
    name="pki-primitives",
    version="3.1.5",
    author="Core Systems Team", 
    description="Provides low-level primitives for PKI operations.", 
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=42.0", 
    ],
)