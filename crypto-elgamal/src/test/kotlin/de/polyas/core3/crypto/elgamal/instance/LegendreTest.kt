package de.polyas.core3.crypto.elgamal.instance

import de.polyas.core3.crypto.std.GuardedSRNG
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
            val a = GuardedSRNG.nextBigIntInRange(TWO, p)
            val aa = (a * a).mod(p)

            val ls = legendreSymbol(aa, p) // expected to be +1
            assertEquals(1, ls.signum())
        }
    }

    @Test
    fun negative() {
        repeat (100) {
            val a = GuardedSRNG.nextBigIntInRange(TWO, p)
            val aa = (a * a).mod(p)
            val ls = legendreSymbol(p - aa, p)
            assertEquals(-1, ls.signum())
        }
    }
}