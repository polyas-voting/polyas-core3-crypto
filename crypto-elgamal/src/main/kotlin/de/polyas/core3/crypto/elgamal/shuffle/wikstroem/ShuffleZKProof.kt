package de.polyas.core3.crypto.elgamal.shuffle.wikstroem

import com.fasterxml.jackson.annotation.JsonProperty
import de.polyas.core3.crypto.annotation.Doc

@Doc("Non-interactive zero-knowledge proof of correct shuffle (Wikstroem et al.)")
data class ShuffleZKProof<GroupElement>(
    @get:JsonProperty("t") val t: ZKPt<GroupElement>,
    @get:JsonProperty("s") val s: ZKPs,
    @get:JsonProperty("c") val c: List<GroupElement>,
    @get:JsonProperty("cHat") val cHat: List<GroupElement>
)