package de.polyas.core3.crypto.std

import java.math.BigInteger
import kotlin.test.*

class GuardedSRNGTest {

    @Test
    fun `sampling bytes`() {
        val bytes1 = GuarderSRNG.nextBytes(1000)
        val bytes2 = GuarderSRNG.nextBytes(1000)

        assertEquals(1000, bytes1.size)
        assertFalse(bytes1 contentEquals bytes2)
    }

    @Test
    fun `sampling messages`() {
        val message1 = GuarderSRNG.nextMessage(1000)
        val message2 = GuarderSRNG.nextMessage(1000)

        assertEquals(1000, message1.length())
        assertNotEquals(message1, message2)
    }

    @Test
    fun `sampled big integers are in the expected range`() {
        val upperBound = BigInteger.valueOf(710000000000000)

        repeat (1000) {
            val sampled = GuarderSRNG.nextBigInt(upperBound)
            assertTrue(sampled >= BigInteger.ZERO)
            assertTrue(sampled < upperBound)
        }
    }

    @Test
    fun `sampled big integers in range are in the expected range`() {
        val lowerBound = BigInteger.valueOf(700000000000000)
        val upperBound = BigInteger.valueOf(710000000000000)

        repeat (1000) {
            val sampled = GuarderSRNG.nextBigIntInRange(lowerBound, upperBound)
            assertTrue(sampled >= lowerBound)
            assertTrue(sampled < upperBound)
        }
    }

    @Test
    fun `begin and end counters`() {
        val end1 = GuarderSRNG.endCount()
        val begin1 = GuarderSRNG.beginCount()
        assertTrue(begin1 >= end1)

        GuarderSRNG.nextMessage(1000)
        val end2 = GuarderSRNG.endCount()
        val begin2 = GuarderSRNG.beginCount()
        assertTrue(begin2 >= end2)
        assertTrue(begin1 <= begin2) // one might expect the difference to be 1, but it can be bigger if tests run in parallel
        assertTrue(end1 <= end2)
    }


    @Test
    fun `begin and end counters inside use`() {
        GuarderSRNG.use {
            val end = GuarderSRNG.endCount()
            val begin = GuarderSRNG.beginCount()
            assertTrue(begin > end)
        }
    }

    @Test
    fun `foo sampling bytes`() {
        val upperBound = BigInteger.valueOf(710000000000000)
        data class Event(val modulus: BigInteger, val value: BigInteger)
        val events = mutableListOf<Event>()
        val myInterceptor = object : GuarderSRNG.Interceptor {
            override fun bytes(bytes: ByteArray) { }
            override fun other() { }
            override fun bi(modulus: BigInteger, value: BigInteger) {
                events += Event(modulus, value)
            }
        }

        GuarderSRNG.setInterceptor(myInterceptor)
        val sampled = GuarderSRNG.nextBigInt(upperBound)
        GuarderSRNG.resetInterceptor()

        val expectedEvent = Event(upperBound, sampled)
        assertTrue(expectedEvent in events)
    }
}
