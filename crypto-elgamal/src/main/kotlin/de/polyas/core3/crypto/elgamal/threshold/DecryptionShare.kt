package de.polyas.core3.crypto.elgamal.threshold

import de.polyas.core3.crypto.elgamal.zkp.EqlogNIZKP
import de.polyas.core3.crypto.annotation.Doc

@Doc("A decryption share (as produced by a decryption teller) along with a zero-knowledge proof of it's correctness.")
data class DecryptionShare<GroupElement>(

    @property:Doc("The index of the decryption teller who produced this decryption share")
    val nr: Int,

    @property:Doc("The decryption share")
    val decShare: GroupElement,

    @property:Doc("A non-interactive zero-knowledge proof of correctness of the contained decryption share.")
    val zkp: EqlogNIZKP.Proof
)
