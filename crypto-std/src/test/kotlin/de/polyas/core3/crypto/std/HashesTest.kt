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

import org.bouncycastle.util.encoders.Hex
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class HashesTest {

    @Test
    fun `sha256 fixture`() {
        val h = Hashes.sha256("abc")
        val expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        assertEquals(expected, h.asHexString())
    }

    @Test
    fun `sha512 fixture`() {
        val h = Hashes.sha512("abc")
        val expected = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        assertEquals(expected, h.asHexString())
    }

    @Test
    fun `hash of a number`() {
        val intValue = 7879
        val h1 = Hashes.sha512 { digest(intValue) }
        val m = buildMessage { put(intValue) }
        val h2 = Hashes.sha512(m)
        assertTrue(h1 contentEquals h2)
    }

    @Test
    fun `sha256 two ways`() {
        val a = Hashes.sha256 {
            digest("abc")
            digest("xyz")
        }
        val b = Hashes.sha256("abcxyz")
        assertTrue(a contentEquals b)
    }

    @Test
    fun `sha512 two ways`() {
        val a = Hashes.sha512 {
            digest("abc")
            digest("xyz")
        }
        val b = Hashes.sha512("abcxyz")
        assertTrue(a contentEquals b)
    }

    @Test
    fun `digesting is compatible with the message builder`() {
        val bytes = Message.fromHexString("aaff0078").asBytes()
        val message = Message.fromHexString("a0f80078000071")
        val h1 = Hashes.sha512 {
            digest(bytes)
            digest(message)
            digest("abc")
            digest(12)
            digest(7888L)
        }
        val m = buildMessage {
            put(bytes)
            put(message)
            put("abc")
            put(12)
            put(7888L)
        }
        val h2 = Hashes.sha512(m)

        assertTrue(h1 contentEquals  h2)
    }

    @Test
    fun `digesting a big integer includes the length`() {
        val bi = BigInteger.valueOf(11223344000090321L)
        val h1 = Hashes.sha512 {
            digest(bi)
        }
        val m = buildMessage {
            val biBytes = bi.toByteArray()
            put(biBytes.size)
            put(biBytes)
        }
        val h2 = Hashes.sha512(m)

        assertTrue(h1 contentEquals  h2)
    }

    @Test
    fun partialDigest() {
        val partialDigest = initialDigestSha512 { digest("aa") }
        val ax1 = partialDigest.continueHashing { digest("xx") }
        val ay1 = partialDigest.continueHashing { digest("yy") }
        val ax2 = Hashes.sha512("aaxx")
        val ay2 = Hashes.sha512("aayy")

        assertTrue(ax1 contentEquals ax2)
        assertTrue(ay1 contentEquals ay2)
    }

    @Test
    fun `partialDigest (non)uniform`() {
        val modulus = BigInteger.valueOf(9999887765)
        val partialDigest = initialDigestSha512 { digest("aa") }
        val ax1 = partialDigest.continueUniformHash(modulus) { digest("xx") }
        val ax2 = uniformHash(modulus) {
            digest("aa")
            digest("xx")
        }

        assertEquals(ax1, ax2)
    }

    companion object {
        fun ByteArray.asHexString(): String = Hex.toHexString(this)
    }
}
