package de.polyas.core3.crypto.elgamal.threshold

import de.polyas.core3.crypto.annotation.Doc

@Doc("A decryption share with an appropriate zero-knowledge proof, computed by a decryption teller in a threshold decryption scheme for a multi-ciphertext")
data class MultiDecryptionShare<GroupElement>(
    @get:Doc("A list of decryption shares, each for one ciphertext of a multi-ciphertext")
    val decryptionShares: List<DecryptionShare<GroupElement>>
)