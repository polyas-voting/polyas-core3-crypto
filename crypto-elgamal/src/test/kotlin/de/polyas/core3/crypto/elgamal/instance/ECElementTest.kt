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

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class ECElementTest {

    @Test
    fun `fromHexString fails on a stupid input`() {
        assertFailsWith<Throwable> {
            ECElement.fromHexString("ffaabb")
        }
    }

    @Test
    fun `serialization-deserialization works`() {
        val om = jacksonObjectMapper()
        val json = om.writeValueAsString(a)
        val a2:ECElement = om.readValue(json)
        assertEquals(a, a2)
    }

    @Test
    fun `different points are not equal`() {
        assertNotEquals(a, b)
    }

    @Test
    fun `the same points are equal`() {
        assertEquals(a, a)
    }

    @Test
    fun `the same values are equal`() {
        val x = a.point()
        val y = b.point()
        val u = BigInteger("7102381523764572652836487")
        val v = BigInteger("818263666367876")

        // we are computing the same value in two different ways
        // (so that the internal representation -- before normalization -- would differ)
        val s = x.add(y).multiply(u).multiply(v)
        val t = x.multiply(u).multiply(v)
                 .add(y.multiply(v).multiply(u))
        val c = ECElement(s)
        val d = ECElement(t)

        // we expect that these are equal and have the same string representation
        assertEquals(c, d)
        assertEquals(c.asHexString(), d.asHexString())
    }

    companion object {
        private val group: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
        private val a = ECElement(group.g.multiply(BigInteger("1237761973553625473453458767")))
        private val b = ECElement(group.g.multiply(BigInteger("77197355368974477425473453458767")))
    }
}

