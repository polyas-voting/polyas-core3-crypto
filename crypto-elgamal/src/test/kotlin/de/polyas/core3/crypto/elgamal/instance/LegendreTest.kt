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

import de.polyas.core3.crypto.std.SRNG
import java.math.BigInteger.TWO
import java.math.BigInteger.ZERO
import kotlin.test.Test
import kotlin.test.assertEquals


class LegendreTest {
    companion object {
        val group = SchnorrGroup.group512
        val p = group.p
    }

    @Test
    fun zero() {
        val ls = legendreSymbol(ZERO, p)
        assertEquals(0, ls.signum())
    }

    @Test
    fun positive() {
        repeat (100) {
            val a = SRNG.nextBigIntInRange(TWO, p)
            val aa = (a * a).mod(p)

            val ls = legendreSymbol(aa, p) // expected to be +1
            assertEquals(1, ls.signum())
        }
    }

    @Test
    fun negative() {
        repeat (100) {
            val a = SRNG.nextBigIntInRange(TWO, p)
            val aa = (a * a).mod(p)
            val ls = legendreSymbol(p - aa, p)
            assertEquals(-1, ls.signum())
        }
    }
}
