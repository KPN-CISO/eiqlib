from setuptools import setup, find_packages

with open('README.md', 'r') as f:
    long_description = f.read()

setup(
    name="eiqlib",
    version="1.0.0",
    author="Sebastiaan Groot",
    author_email="sebastiaang@kpn-cert.nl",
    description="A python3 library for interacting with EclecticIQ",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/KPN-CISO/eiqlib",
    packages=find_packages(),
    classifiers=(
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
)
