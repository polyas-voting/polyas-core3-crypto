/*
 * Copyright 2025 Polyas GmbH
 *
 * Licensed under GNU Affero General Public License v3.0; you may not use
 * this file except in compliance with the License. You may obtain a copy of
 * the License at https://www.gnu.org/licenses/agpl-3.0.en.html.
 * This software is distributed WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
 * either express or implied.
 */
package de.polyas.core3.crypto.elgamal.instance

import de.polyas.core3.crypto.elgamal.Ciphertext
import de.polyas.core3.crypto.elgamal.Cryptosystem
import de.polyas.core3.crypto.std.SRNG
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals

class ElgamalGroupTest {
    private val numTests = 100

    @Test
    fun homomorphism() {
        val g = SchnorrGroup.group1536
        for (i in 0 until numTests) {
            // g^(ab+c)/g^c = g^ab
            val a = randomSafeZq(g)
            val b = randomSafeZq(g)
            val c = randomSafeZq(g)

            with (g) {
                val ab = a.multiply(b).mod(g.order)
                val abPlusC = ab.add(c).mod(g.order)
                val left = g.powerOfG(ab)
                val right = g.powerOfG(abPlusC) * g.inverse(g.powerOfG(c))
                assertEquals(left, right)
            }
        }
    }

    @Test
    fun encoding() {
        val g = SchnorrGroup.group1536
        for (i in 0 until numTests) {
            val message = randomSafeZq(g)
            assertEquals(g.decode(g.encode(message)), message)
        }
    }

    @Test
    fun identity() {
        val g = SchnorrGroup.group1536
        for (i in 0 until numTests) {
            val randomElement = g.encode(randomSafeZq(g))
            val randomInteger = randomSafeZq(g)
            with(g) {
                assertEquals(identity * randomElement, randomElement) // 1 * x = x
                assertEquals(identity pow randomInteger, identity) // 1^x = 1
            }
        }
    }

    @Test
    fun associativity() {
        val g = SchnorrGroup.group1536
        for (i in 0 until numTests) {
            val a = g.encode(randomSafeZq(g))
            val b = g.encode(randomSafeZq(g))
            val c = g.encode(randomSafeZq(g))
            assertEquals((a * b) * c, a * (b * c))
        }
    }

    @Test
    fun commutativity() {
        val g = SchnorrGroup.group1536
        for (i in 0 until numTests) {
            val a = g.encode(randomSafeZq(g))
            val b = g.encode(randomSafeZq(g))
            assertEquals(a * b, b * a)
        }
    }

    @Test
    fun inverse() { // Inverse
        val g = SchnorrGroup.group1536
        for (i in 0 until numTests) {
            with (g) {
                val a = g.encode(randomSafeZq(g))
                assertEquals(g.identity, a * g.inverse(a)) // a * a^-1 = 1
            }
        }
    }

    @Test
    fun powTest() {
        val g = SchnorrGroup.group1536
        for (i in 0 until numTests) {
            val plaintext = g.encode(randomSafeZq(g))
            val c = randomSafeZq(g)
            val cInv = c.modInverse(g.order)
            with(g) {
                assertEquals(plaintext.pow(c).pow(cInv), plaintext)
            }
        }
    }

    @Test
    fun test() {
        val g = SchnorrGroup.group1536

        val cs = Cryptosystem(g)
        val sk = BigInteger.valueOf(89862778)
        val pk = g.powerOfG(sk)
        val plaintext = BigInteger.valueOf(1234)
        val encrypted: Ciphertext<BigInteger> = cs.encrypt(pk, plaintext)
        val decrypted = cs.decrypt(sk, encrypted)
        assertEquals(plaintext, decrypted)
    }

    private companion object {
        fun randomSafeZq(g: SchnorrGroup): BigInteger =
            SRNG.nextBigIntInRange(BigInteger.valueOf(2), g.order)
    }
}
