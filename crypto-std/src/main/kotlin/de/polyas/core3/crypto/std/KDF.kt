/*
 * Copyright 2025 Polyas GmbH
 *
 * Licensed under GNU Affero General Public License v3.0; you may not use
 * this file except in compliance with the License. You may obtain a copy of
 * the License at https://www.gnu.org/licenses/agpl-3.0.en.html.
 * This software is distributed WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
 * either express or implied.
 */
package de.polyas.core3.crypto.std

import java.math.BigInteger
import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Key derivation function implementing algorithm 5.1 from KDF in Counter Mode
 * NIST SP 800-108 and also part of the algorithm A.2.3 (Verifiable Canonical Generation of
 * the Generator g) from NIST fips186-4.
 */
object KDF {

    /**
     * Key derivation function which produces a pseudo-random byte string of the given
     * length [targetByteLength] derived from the key [seed] and, so-called, domain
     * parameters [label] and [context].
     *
     * This implementation uses (a variant of) the NIST SP 800-108 standard.
     *
     * @param seed  The seed for key derivation
     * @param targetByteLength   The length of the data to be derived in bytes
     * @param label   A bit string that identifies the purpose of the derived key material
     * @param context  A bit string specifying the additional context
     * @return byte array of length 'targetByteLength' derived bytes
     */
	fun kdfCounterMode(seed: ByteArray, targetByteLength: Int, label: ByteArray, context: ByteArray): ByteArray =
        ByteArray(targetByteLength).also { bytes ->
            kdfCounterModeWithConsumer(seed, targetByteLength, label, context) { index: Int, b: Byte ->
                bytes[index] = b
            }
        }

    /**
     * Returns a number in the range [0, [modulus]) generated pseudo-randomly using the
     * given [seed]. The numbers are distributed (pseudo-)uniformly in the given
     * range.
     */
	fun numberFromSeed(modulus: BigInteger, seed: ByteArray): BigInteger =
        numbersFromSeed(modulus, seed).first()

    /**
     * Returns a sequence of integers in the range from 0 to [upperBound] (exclusive),
     * derived from the given [seed].
     *
     * The used method is based on algorithm A.2.3 (Verifiable Canonical Generation of the Generator g)
     * from NIST fips186-4 (this method implements part of this algorithm).
     *
     * @return A stream of values from [0, [upperBound])
     */
    fun numbersFromSeed(upperBound: BigInteger, seed: ByteArray): Sequence<BigInteger> =
        numbersFromSeed(upperBound.bitLength(), seed)
            .filter { w: BigInteger -> w < upperBound }


    // Implementation

    private val genLabel = "generator".toByteArray()
    private val genContext = "Polyas".toByteArray()

    private fun kdfCounterModeWithConsumer(
        seed: ByteArray,
        targetByteLength: Int,
        label: ByteArray,
        context: ByteArray,
        byteConsumer: (index: Int, value: Byte) -> Unit
    ) {
        val sha512Hmac = initializeMac(seed)
        var resultIndex = 0
        var blockIndex = 0
        while (resultIndex < targetByteLength) {
            val nextBlock = block(sha512Hmac, blockIndex, context, label, targetByteLength)
            var j = 0
            while (j < nextBlock.size && resultIndex < targetByteLength) {
                byteConsumer(resultIndex++, nextBlock[j])
                ++j
            }
            blockIndex++
        }
    }

    /**
     * Returns a sequence of integers of the given bit length [bitLength], derived from the given [seed].
     * @return A stream of values from [0, 2^bits)
     */
    private fun numbersFromSeed(bitLength: Int, seed: ByteArray): Sequence<BigInteger> {
        return (1 .. Int.MAX_VALUE).asSequence().map { count: Int ->
            val bytes = buildMessage { put(seed); put(count) }.asBytes()
            BigInteger(kdfCounterModeBitsWithLeadingZero(bytes, bitLength))
        }
    }

    /**
     * Similar to [kdfCounterMode], but it takes the expected length in bits (not bytes)
     * and with an additional leading 0 attached to the result.
     *
     * Used to create big integers of the given bit length, where the leading 0 is needed
     * in order to prevent the resulting byte string to be interpreted as a negative number
     * (when the most significant bit is 1).
     */
    private fun kdfCounterModeBitsWithLeadingZero(keyDerivationKey: ByteArray, targetBitLength: Int): ByteArray {
        require(targetBitLength > 0) { "Target bit length is negative ($targetBitLength)" }
        val byteLength = roofDiv8(targetBitLength)

        // generates
        val result = ByteArray(byteLength + 1)
        kdfCounterModeWithConsumer(keyDerivationKey, byteLength, genLabel, genContext) { ind: Int, b: Byte ->
            result[ind + 1] = b
        }
        val d = byteLength * 8 - targetBitLength
        val mask = 0xff shr d
        result[1] = (result[1].toInt() and mask).toByte()
        return result
    }

    private fun initializeMac(keyDerivationKey: ByteArray): Mac {
        val sha512Hmac = Mac.getInstance("HmacSHA512")
        val keySpec = SecretKeySpec(keyDerivationKey, "HmacSHA512")
        sha512Hmac.init(keySpec)
        return sha512Hmac
    }

    private fun block(
        sha512HMAC: Mac,
        blockIndex: Int,
        context: ByteArray,
        label: ByteArray,
        targetByteLength: Int
    ): ByteArray {
        sha512HMAC.update(intAsBytes(blockIndex))
        sha512HMAC.update(label)
        sha512HMAC.update(0.toByte())
        sha512HMAC.update(context)
        sha512HMAC.update(intAsBytes(targetByteLength))
        return sha512HMAC.doFinal()
    }

    private fun intAsBytes(k: Int): ByteArray =
        ByteBuffer.allocate(4).putInt(k).array()

    private fun roofDiv8(a: Int): Int =
        a / 8 + if (a % 8 == 0) 0 else 1
}
