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
import java.security.SecureRandom
import java.util.Random
import java.util.concurrent.atomic.AtomicLong

/**
 * A guarder (instrumented) secure random number generator, backed by an instance of SecureRandom.
 *
 * **The instrumentation** allows one to see how many users (client code instances)
 * are using the underlying instance of SecureRandom at a given time.
 * In order to use the encapsulated SecureRandom object, the user code must first _lend_ it.
 * Each lending increases the 'begin' counter at the beginning of the lend and
 * then increases the 'end' counter at the end of the lend.
 *
 * The motivation for this instrumentation is that, in some implementations,
 * SecureRandom objects can block waiting for enough entropy te be gathered.
 * This may block the operations of the whole system. This instrumentation allows
 * an application to detect/monitor such situations, by interpreting the values
 * of the 'begin' and 'end' counters: if the difference between these two counters
 * is big, it means that there are many operations that started, but not finished,
 * which may indicate a dried-out entropy pool.
 */
object SRNG: RandomBigIntSource {
    private val random : Random = SecureRandom.getInstanceStrong() // the Random which backs this object
    private val beginUse = AtomicLong(0L)
    private val endUse = AtomicLong(0L)

    /**
     * Returns the `begin` lending counter.
     */
    fun beginCount(): Long = beginUse.get()

    /**
     * Returns the `end` lending counter.
     */
    fun endCount(): Long = endUse.get()

    /**
     * Fills up the given buffer [bytes] with randomly sampled bytes.
     */
    fun nextBytes(bytes: ByteArray) {
        lend { r: Random ->
            r.nextBytes(bytes)
        }
    }

    /**
     * Samples [length] random bytes
     */
    fun nextBytes(length: Int): ByteArray {
        val result = ByteArray(length)
        nextBytes(result)
        return result
    }

    /**
     * Samples [length] random bytes and returns them as a [Message].
     */
    fun nextMessage(length: Int): Message {
        return Message.fromBytes(nextBytes(length))
    }

    /**
     * Samples a random [BigInteger] in the range [0, upperBound).
     */
    override fun nextBigInt(upperBound: BigInteger): BigInteger =
        nextBigIntImpl(upperBound)

    /**
     * Samples a random [BigInteger] in the range [lower, upper).
     */
    fun nextBigIntInRange(lower: BigInteger, upper: BigInteger): BigInteger =
        lower + nextBigInt(upper - lower)

    /**
     * Provides the underlying SRND for bulk usage:
     * The 'begin' lending counter is incremented once before the block [userOfRandom]
     * is executed with the underlying SRND; the 'end' lending counter is incremented
     * after the execution of this block has finished.
     */
    fun <T> use(userOfRandom: (Random) -> T): T {
        val result = lend(userOfRandom)
        return result
    }

    private fun nextBigIntImpl(modulus: BigInteger): BigInteger {
        repeat(1000) {
            val i = lend { r: Random? -> BigInteger(modulus.bitLength(), r) }
            if (i < modulus) {
                return i
            }
        }
        error("Failed to generate random BigInteger after 1000 attempts - possible RNG failure")
    }

    private fun <T> lend(userOfRandom: (Random) -> T): T {
        beginUse.incrementAndGet() // increase the count of started use instances
        return try {
            userOfRandom(random) // we are lending our random for some usage
        } finally {
            endUse.incrementAndGet() // increase the count of finished use instances
        }
    }
}

interface RandomBigIntSource {
    fun nextBigInt(upperBound: BigInteger): BigInteger
}
