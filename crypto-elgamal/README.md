# Polyas-Core3 Crypto-Elgamal

This module contains an implementation of Elgamal-based cryptographic algorithms
such as:

- Elgamal-based encryption and verifiable decryption,
- standard zero-knowledge proofs,
- threshold (verifiable) decryption,
- verifiable shuffle (the algorithm by Wikstroem et al.)

The algorithms are expressed over an abstract 
[cyclic group](src/main/java/de/polyas/core3/crypto/elgamal/CyclicGroup.kt),
for which two instantiations are provided: 

 - the Schnorr group (the group of quadratic residues modulo a safe prime),
 - an instanced based on elliptic curves `secp256k1`.

