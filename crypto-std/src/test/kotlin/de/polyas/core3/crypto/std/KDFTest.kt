package de.polyas.core3.crypto.std

import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class KDFTest {

    @Test
    fun kdfCounterModeBytes() {
        val b = KDF.kdfCounterMode(seed, 300, label, context)
        assertEquals(300, b.size.toLong())
    }

    @Test
    fun numbersFromSeed() {
        val upperBound = BigInteger("188888887777777666666555555544444443433333322222221")

        KDF.numbersFromSeed(upperBound, seed).take(100).forEach {
            assertTrue(it >= 0.toBigInteger() && it < upperBound)
        }
    }

    @Test
    fun numbersFromSeedSaturation() {
        val upperBound = 5
        val set = KDF.numbersFromSeed(upperBound.toBigInteger(), seed)
            .take(100)
            .toSet()
        val expected = (0 until upperBound)
            .map { it.toBigInteger() }
            .toSet()
        assertEquals(expected, set)
    }

    companion object {
        private val seed = "kdk".toByteArray()
        val label = "label".toByteArray()
        val context = "context".toByteArray()
    }
}