# setup.py

from setuptools import setup, find_packages

setup(
    name="pki-primitives",  # The installable name
    version="1.0.3",       # Bump the version again
    author="Core Systems Team",
    description="Provides low-level primitives for PKI operations.",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    include_package_data=True,    
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=42.0",
    ],
)