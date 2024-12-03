# Polyas-Core3 Crypto-ElGamal

This module contains an implementation of Elgamal-based cryptographic algorithms
such as:

- ElGamal-based encryption and verifiable decryption,
- standard zero-knowledge proofs,
- threshold (verifiable) decryption,
- verifiable shuffle (the algorithm by Wikstroem et al.)

The algorithms are expressed over an abstract 
[cyclic group](src/main/kotlin/de/polyas/core3/crypto/elgamal/CyclicGroup.kt),
for which two instantiations are provided: 

 - the Schnorr group (the group of quadratic residues modulo a safe prime);
   this group is used mostly for testing,
 - an instanced based on elliptic curves `secp256k1`.

