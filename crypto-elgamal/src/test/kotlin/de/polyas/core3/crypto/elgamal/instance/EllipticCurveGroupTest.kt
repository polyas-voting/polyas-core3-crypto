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

import de.polyas.core3.crypto.elgamal.Cryptosystem
import de.polyas.core3.crypto.elgamal.instance.EllipticCurveInst.Companion.curve
import de.polyas.core3.crypto.std.SRNG
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals

class EllipticCurveGroupTest {
    // We do not test closure
    private val numTests = 100

    // We do not test closure
    @Test
    fun checkHomomorphism() {
        val g = EllipticCurveInst()
        for (i in 0 until numTests) {
            //g^(ab+c)/g^c = g^ab
            val a = randomSafeElement(g)
            val b = randomSafeElement(g)
            val c = randomSafeElement(g)

            val ab = a.multiply(b).mod(g.order)
            val abPlusC = ab.add(c).mod(g.order)
            val left = g.powerOfG(ab)
            with (g) {
                val right = g.powerOfG(abPlusC) * g.inverse(g.powerOfG(c))
                assertEquals(left, right)
            }
        }

        // val a = randomSafeElement(g)
        // val b = randomSafeElement(g)
    }

    @Test
    fun checkEncode() {
        val g = EllipticCurveInst()
        for (i in 0..999) {
            val message = randomSafeElement(g)
            assertEquals(g.decode(g.encode(message)), message)
        }
    }

    @Test
    fun one() { // Identity
        val g = EllipticCurveInst()
        for (i in 0..999) {
            val randomElement = g.encode(randomSafeElement(g))
            val randomInteger = random(g.order)
            with (g) {
                assertEquals(g.identity * randomElement, randomElement) // 1 * x = x
                assertEquals(g.identity.pow(randomInteger), g.identity) // 1^x = 1
            }
        }
    }

    @Test
    fun associativity() { // Associativity
        val g = EllipticCurveInst()
        for (i in 0..999) {
            val a = g.encode(randomSafeElement(g))
            val b = g.encode(randomSafeElement(g))
            val c = g.encode(randomSafeElement(g))
            with (g) {
                assertEquals((a * b) * c, a * (b * c))
            }
        }
    }

    @Test
    fun commutativity() { // Commutativity
        val g = EllipticCurveInst()
        for (i in 0..999) {
            val a = g.encode(randomSafeElement(g))
            val b = g.encode(randomSafeElement(g))
            with (g) {
                assertEquals(a * b, b * a)
            }
        }
    }

    @Test
    fun inverse() { // Inverse
        val g = EllipticCurveInst()
        for (i in 0..999) {
            with (g) {
                val a = encode(randomSafeElement(g))
                assertEquals(a * inverse(a), identity) // a * a^-1 = 1
            }
        }
    }

    @Test
    fun powTest() {
        val g = EllipticCurveInst()
        for (i in 0..999) {
            val plaintext = g.encode(randomSafeElement(g))
            val c = random(g.order)
            val cInv = c.modInverse(g.order)
            with (g) {
                assertEquals(plaintext.pow(c).pow(cInv), plaintext)
            }
        }
    }

    @Test
    fun fromBytes() {
        val g = EllipticCurveInst()
        for (i in 0..99) {
            val a = g.powerOfG(random(g.order))
            assertEquals(g.fromBytes(g.asBytes(a))!!, a)
        }
    }

    @Test
    fun test() {
        val g = EllipticCurveInst()

        // This code uses a concrete instance of ElGamal group
        val cs = Cryptosystem(g)
        val sk = BigInteger.valueOf(89862778)
        val pk = g.powerOfG(sk)
        val plaintext = BigInteger.valueOf(1234)
        val encrypted = cs.encrypt(pk, plaintext)
        val decrypted = cs.decrypt(sk, encrypted)
        assertEquals(plaintext, decrypted)
    }

    @Test
    fun residueLegendreSymbol() {
        val p = curve.q
        for (i in 0..99) {
            val x = random(p)
            val sqrX = x.modPow(BigInteger.valueOf(2), p)
            assertEquals(1, legendreSymbol(sqrX, p).signum())
        }
    }

    companion object {
        fun random(upperBound: BigInteger?): BigInteger {
            return SRNG.nextBigIntInRange(BigInteger.valueOf(2), upperBound!!)
        }

        fun randomSafeElement(g: EllipticCurveInst): BigInteger {
            return random(g.messageUpperBound())
        }
    }
}
