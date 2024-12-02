package de.polyas.core3.crypto.elgamal

import com.fasterxml.jackson.annotation.JsonProperty
import de.polyas.core3.crypto.annotation.Doc

@Doc("ElGamal ciphertext represented as two group elements x and y")
data class Ciphertext<GroupElement> (
    @get:JsonProperty("x") val x: GroupElement,
    @get:JsonProperty("y") val y: GroupElement
)