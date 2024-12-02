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
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/**
 * Convenience wrappers for standard hashing functions.
 */
object Hashes {

    fun sha256(message: Message): ByteArray =
        sha256(message.asBytes())

    fun sha256(str: String): ByteArray =
        sha256(str.toByteArray(StandardCharsets.UTF_8))

	fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256")
            .digest(bytes)

    fun sha512(message: Message): ByteArray =
        sha512(message.asBytes())

    fun sha512(str: String): ByteArray =
        sha512(str.toByteArray(StandardCharsets.UTF_8))

    fun sha512(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-512")
            .digest(bytes)

    /**
     * Computes the SHA-256 hash function from the data provided by the [DigestCtx.digest] function,
     * as in the following example:
     * ```
     *  sha256 {
     *      digest(data1)
     *      digest(data2)
     *      for (data in dataList) {
     *          digest(data)
     *      }
     *  }
     * ```
     */
    inline fun sha256(digestBlock: DigestCtx.() -> Unit): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        val ctx = DigestCtx(md)
        ctx.digestBlock()
        return md.digest()
    }

    /**
     * Computes the SHA-512 hash function from the data provided by the [DigestCtx.digest] function,
     * as in the following example:
     * ```
     *  sha256 {
     *      digest(data1)
     *      digest(data2)
     *      for (data in dataList) {
     *          digest(data)
     *      }
     *  }
     * ```
     */
    inline fun sha512(digestBlock: DigestCtx.() -> Unit): ByteArray {
        val md = MessageDigest.getInstance("SHA-512")
        val ctx = DigestCtx(md)
        ctx.digestBlock()
        return md.digest()
    }
}

/**
 * Returns the digest of the supplied data as a big integer distributed
 * pseudo-uniformly in the range [0, modulus).
 *
 * The data is supplied by the [digestBlock] using the `digest` function:
 *
 *     val hash = uniformHash (modulus) {
 *         digest(valueA)
 *         ...
 *         digest(valueB)
 *     }
 */
fun uniformHash(modulus: BigInteger, digestBlock: DigestCtx.() -> Unit): BigInteger {
    val digest = Hashes.sha512(digestBlock)
    return KDF.numberFromSeed(modulus, digest)
}

/**
 * Starts digesting data with SHA-512 and returns the (initial) partial digest.
 *
 * The returned [PartialDigest] encapsulates a [MessageDigest] object and
 * allows one to pick up digesting at a later point, using one of the `continue*`
 * methods of [PartialDigest].
 *
 * The same [PartialDigest] object can be used multiple times to
 * continue digesting independently:
 *
 * ```
 *    val initial = initialDigest {
 *        digest("a")
 *    }
 *
 *    val x = initialDigest.continueUniformHash(modulus) {
 *        digest ("b")
 *    }
 *    // x is the hash of "a" and "b"
 *
 *    val y = initialDigest.continueUniformHash(modulus) {
 *        digest ("c")
 *    }
 *    // y is the hash of "a" and "c"
 *
 *  ```
 *
 * @return A partial digest object which can be used to continue digesting.
 */
fun initialDigestSha512(block: DigestCtx.() -> Unit): PartialDigest {
    val ctx = DigestCtx(MessageDigest.getInstance("SHA-512"))
    ctx.block()
    return PartialDigest(ctx.md)
}

/**
 * A partial (intermediate) result of digesting, allowing to independently continue digesting.
 *
 * @see initialDigestSha512
 */
class PartialDigest(private val md: MessageDigest) {

    /**
     * Continues digesting and returns the hash as a byte array.
     */
    fun continueHashing(block: DigestCtx.() -> Unit): ByteArray {
        val ctx = DigestCtx(md.clone() as MessageDigest)
        ctx.block()
        return ctx.md.digest()
    }

    /**
     * Continues digesting and returns the result as a big integer distributed pseudo-uniformly
     * in the range [0, modulus).
     */
    fun continueUniformHash(modulus: BigInteger, block: DigestCtx.() -> Unit): BigInteger {
        val digest = continueHashing(block)
        return KDF.numberFromSeed(modulus, digest)
    }
}

/**
 * A context for hashing functions.
 */
@JvmInline value class DigestCtx(internal val md: MessageDigest) {

    fun digest(bytes: ByteArray) {
        md.update(bytes)
    }

    fun digest(message: Message) {
        md.update(message.asBytes())
    }

    fun digest(vararg bs: ByteArray) {
        for (b in bs) md.update(b)
    }

    fun digest(string: String, charset: Charset = charset("UTF-8")) {
        md.update(string.toByteArray(charset))
    }

    fun digest(i: Int) {
        val bytes = buildMessage { put(i) }
        md.update(bytes.asBytes())
    }

    fun digest(i: Long) {
        val bytes = buildMessage { put(i) }
        md.update(bytes.asBytes())
    }

    /**
     * It digests the byte representation of the given [BigInteger] prepended by its length.
     */
    fun digest(bigInteger: BigInteger) {
        val bytes = bigInteger.toByteArray()
        digest(bytes.size)
        md.update(bytes)
    }
}
