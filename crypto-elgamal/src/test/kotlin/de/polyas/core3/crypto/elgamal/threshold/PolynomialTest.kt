/*
 * Copyright 2025 Polyas GmbH
 *
 * Licensed under GNU Affero General Public License v3.0; you may not use
 * this file except in compliance with the License. You may obtain a copy of
 * the License at https://www.gnu.org/licenses/agpl-3.0.en.html.
 * This software is distributed WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
 * either express or implied.
 */
package de.polyas.core3.crypto.elgamal.threshold

import de.polyas.core3.crypto.elgamal.instance.SchnorrGroup
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PolynomialTest {

    @Test
    fun evaluation() {
        val group = SchnorrGroup.group512
        val polynomial = Polynomial.random(4, group)
        val x = BigInteger.valueOf(8618562346)

        val expected = (
                polynomial.coefficients[3] * (x*x*x) +
                polynomial.coefficients[2] * (x*x) +
                polynomial.coefficients[1] * x +
                polynomial.coefficients[0]
        ).mod(group.q)

        val evaluated = polynomial.valueAt(group, x)
        assertEquals(expected, evaluated)
    }

    @Test
    fun `random polynomial`() {
        val group = SchnorrGroup(BigInteger.valueOf(2), BigInteger.valueOf(5))
        val n = 10 // number of coefficients
        repeat (100) {
            val polynomial = Polynomial.random(n, group)

            assertEquals(n, polynomial.coefficients.size)
            assertTrue(polynomial.coefficients[n - 1] != BigInteger.ZERO)
            polynomial.coefficients.forEach { coefficient ->
                assertTrue(coefficient >= BigInteger.ZERO && coefficient < group.q)
            }
        }
    }

    @Test
    fun blind() {
        val group = SchnorrGroup.group512
        val polynomial = Polynomial.random(10, group)
        val blinded = polynomial.blindPolynomial(group)

        assertEquals(polynomial.coefficients.size, blinded.size)
        polynomial.coefficients.zip(blinded).forEach { (c, b) ->
            assertEquals(group.powerOfG(c), b)
        }
    }
}
