# Polyas-Core3 Crypto-Std

This module contains convenience wrappers for standard cryptographic
methods and some utilities built on top of standard cryptographic
primitives.

 * __Functionality for creating and manipulating messages__ (byte
   arrays); see class `Message`.

 * __Wrappers for standard cryptographic methods__

     - symmetric and asymmetric encryption,
     - signing and signature verification,
     - hashing.

 * __Utilities built on top of standard cryptographic primitives__

     - stream encryption,
     - key derivation,
     - hashing into a space of big integers ($Z_q$)
     - deterministic encryption intended for encryption of keys in key-value 
       data stores.
