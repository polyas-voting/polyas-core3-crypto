package de.polyas.core3.crypto.elgamal

import java.math.BigInteger

/**
 * A list of big integers representing a long plaintext message.
 */
data class MultiPlaintext(
    val plaintexts: List<BigInteger>
) {
    constructor(n: Int, generator: (Int) -> BigInteger) : this(List(n, generator))

    fun size(): Int = plaintexts.size

    operator fun get(i: Int): BigInteger = plaintexts[i]
}
