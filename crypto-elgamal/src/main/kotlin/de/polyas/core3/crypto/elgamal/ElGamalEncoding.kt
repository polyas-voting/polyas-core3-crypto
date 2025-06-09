/*
 * Copyright 2025 Polyas GmbH
 *
 * Licensed under GNU Affero General Public License v3.0; you may not use
 * this file except in compliance with the License. You may obtain a copy of
 * the License at https://www.gnu.org/licenses/agpl-3.0.en.html.
 * This software is distributed WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
 * either express or implied.
 */
package de.polyas.core3.crypto.elgamal

import de.polyas.core3.crypto.std.Message
import de.polyas.core3.crypto.std.buildByteArray
import de.polyas.core3.crypto.std.buildMessage
import java.math.BigInteger

/**
 * Utilities for encoding and decoding messages (byte arrays) as sequences of big integers
 * for ElGamal-based encryption.
 */
object ElGamalEncoding {
    /**
     * Encodes the given string as a sequence of integers which are valid
     * plaintexts for the given group (which means integers in the range that can
     * be encoded as group elements).
     */
	fun encodeString(msg: String, group: CyclicGroup<*>): List<BigInteger> =
	    encodeBytes(msg.toByteArray(Charsets.UTF_8), group)

    /**
     * Encodes the given byte array as a sequence of integers which are valid
     * plaintexts for the given group (which means integers in the range that can
     * be encoded as group elements).
     */
    fun encodeBytes(bytes: ByteArray, group: CyclicGroup<*>): List<BigInteger> =
        encodeBytes(bytes, group.messageUpperBound())

    /**
     * Encodes the given array of bytes as a sequence of integers in [0, upperBound]
     */
    fun encodeBytes(bytes: ByteArray, upperBound: BigInteger): List<BigInteger> {
        val blockSize = blockSize(upperBound)
        val padded = padded(bytes, blockSize)
        var blockBegin = 0

        return buildList {
            while (blockBegin < padded.size) {
                val block = copyOfRangeWithLeadingZero(
                    padded, blockBegin, kotlin.math.min(padded.size, blockBegin + blockSize)
                )
                add(BigInteger(block))
                blockBegin += blockSize
            }
        }
    }

    /**
     * Decodes a sequence of integers (in Zq) back to a message.
     */
    fun decodeToMessage(plaintext: List<BigInteger>, group: CyclicGroup<*>): Result<Message> =
        kotlin.runCatching {
            decodeToMessageUnsafe(plaintext, group.messageUpperBound())
        }

    /**
     * Decodes a sequence of integers (of Zq) back into a string.
     */
    fun decodeToString(plaintexts: List<BigInteger>, group: CyclicGroup<*>): Result<String> =
        decodeToMessage(plaintexts, group).mapCatching { m: Message -> m.asUtf8String() }

    private fun decodeToMessageUnsafe(plaintext: List<BigInteger>, upperBound: BigInteger): Message {
        val bytes = decodeToMessageWithPad(plaintext, upperBound)

        return buildMessage {
            val padSize = 0x000000ff and bytes[1] + 256 * (0x000000ff * bytes[0])
            for (l in bytes.size - padSize until bytes.size) {
                require(bytes[l] == ZERO_BYTE) { "Padding should contain only zeros" }
            }
            // cut off two bytes from the left (the byte with the pad size), and padSize bytes from the right
            put(bytes, 2, bytes.size - padSize)
        }
    }

    private fun decodeToMessageWithPad(plaintext: List<BigInteger>, upperBound: BigInteger): ByteArray {
        val blockSize = blockSize(upperBound)

        return buildByteArray {
            for (p in plaintext) {
                val arr = p.toByteArray()
                if (arr.size > blockSize) {
                    require(arr[0] == ZERO_BYTE)
                    put(arr, 1)
                } else if (arr.size < blockSize) {
                    val n = blockSize - arr.size
                    for (i in 0 until n) {
                        putByte(0.toByte())
                    }
                    put(arr)
                } else {
                    put(arr)
                }
            }
        }
    }

    private fun padSize(bytes: ByteArray, blocksize: Int): Int {
        val remainder = (bytes.size + 2) % blocksize // we secure two extra bytes (the "+ 2") for the pad size
        return (blocksize - remainder) % blocksize // 0 if blocksize == 0; blocksize - reminder otherwise
    }

    /**
     * Returns a version of 'bytes' with an appended pad, where a pad consists of zeros,
     * and prepended the length of the pad (one byte), where the length of the pad
     * is such that the size of the resulting array divides the block size.
     */
    private fun padded(bytes: ByteArray, blocksize: Int): ByteArray {
        return buildByteArray {
            val padSize = padSize(bytes, blocksize) // the size of the pad
            putShort(padSize.toShort()) // prepend the message with the pad size (one byte)
            put(bytes) // the message itself
            for (i in 0 until padSize) { // append the pad
                putByte(0.toByte())
            }
        }
    }

    private fun copyOfRangeWithLeadingZero(original: ByteArray, from: Int, to: Int): ByteArray {
        val newLength = to - from
        require(newLength >= 0) { "$from > $to" }
        val copy = ByteArray(newLength + 1)
        copy[0] = 0
        System.arraycopy(
            original, from, copy, 1,
            Math.min(original.size - from, newLength)
        )
        return copy
    }

    internal fun blockSize(q: BigInteger): Int {
        return (q.bitLength() - 1) / 8
    }

    private const val ZERO_BYTE: Byte = 0
}
