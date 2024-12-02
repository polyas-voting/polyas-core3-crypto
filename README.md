# Polyas Core 3 Crypto

Cryptographic libraries used by POLYAS Core 3 e-voting systems 

## The content of this repository

This project contains the following modules:

* **[crypto-std](crypto-std/README.md)**  
 
  Wrappers for common crypto primitives and utilities built on top of them.

* **[crypto-elgamal](crypto-elgamal/README.md)**  
 
  Implementation of ElGamal-based algorithms, including:
  verifiable threshold decryption and
  zero-knowledge proof of correct shuffle


## Building and testing

For building and testing run

```sh
mvn install
```