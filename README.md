# Polyas Core 3 Crypto

This repository contains the cryptographic library used by POLYAS Core 3
e-voting platform. 

## The content of this repository
It consists of the following modules:

* **crypto-std**  
  Wrappers for common crypto primitives and utilities built on top of them.

* **crypto-elgamal**  
  Implementation of ElGamal-based algorithms, including:
  verifiable threshold decryption and
  zero-knowledge proof of correct shuffle


## Building and testing

For building and testing run

```sh
mvn install
```