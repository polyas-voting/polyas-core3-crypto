package de.polyas.core3.crypto.std

import java.math.BigInteger
import kotlin.test.*

class GuardedSRNGTest {

    @Test
    fun `sampling bytes`() {
        val bytes1 = GuardedSRNG.nextBytes(1000)
        val bytes2 = GuardedSRNG.nextBytes(1000)

        assertEquals(1000, bytes1.size)
        assertFalse(bytes1 contentEquals bytes2)
    }

    @Test
    fun `sampling messages`() {
        val message1 = GuardedSRNG.nextMessage(1000)
        val message2 = GuardedSRNG.nextMessage(1000)

        assertEquals(1000, message1.length())
        assertNotEquals(message1, message2)
    }

    @Test
    fun `sampled big integers are in the expected range`() {
        val upperBound = BigInteger.valueOf(710000000000000)

        repeat (1000) {
            val sampled = GuardedSRNG.nextBigInt(upperBound)
            assertTrue(sampled >= BigInteger.ZERO)
            assertTrue(sampled < upperBound)
        }
    }

    @Test
    fun `sampled big integers in range are in the expected range`() {
        val lowerBound = BigInteger.valueOf(700000000000000)
        val upperBound = BigInteger.valueOf(710000000000000)

        repeat (1000) {
            val sampled = GuardedSRNG.nextBigIntInRange(lowerBound, upperBound)
            assertTrue(sampled >= lowerBound)
            assertTrue(sampled < upperBound)
        }
    }

    @Test
    fun `begin and end counters`() {
        val end1 = GuardedSRNG.endCount()
        val begin1 = GuardedSRNG.beginCount()
        assertTrue(begin1 >= end1)

        GuardedSRNG.nextMessage(1000)
        val end2 = GuardedSRNG.endCount()
        val begin2 = GuardedSRNG.beginCount()
        assertTrue(begin2 >= end2)
        assertTrue(begin1 <= begin2) // one might expect the difference to be 1, but it can be bigger if tests run in parallel
        assertTrue(end1 <= end2)
    }


    @Test
    fun `begin and end counters inside use`() {
        GuardedSRNG.use {
            val end = GuardedSRNG.endCount()
            val begin = GuardedSRNG.beginCount()
            assertTrue(begin > end)
        }
    }

    @Test
    fun `foo sampling bytes`() {
        val upperBound = BigInteger.valueOf(710000000000000)
        data class Event(val modulus: BigInteger, val value: BigInteger)
        val events = mutableListOf<Event>()
        val myInterceptor = object : GuardedSRNG.Interceptor {
            override fun bytes(bytes: ByteArray) { }
            override fun other() { }
            override fun bi(modulus: BigInteger, value: BigInteger) {
                events += Event(modulus, value)
            }
        }

        GuardedSRNG.setInterceptor(myInterceptor)
        val sampled = GuardedSRNG.nextBigInt(upperBound)
        GuardedSRNG.resetInterceptor()

        val expectedEvent = Event(upperBound, sampled)
        assertTrue(expectedEvent in events)
    }
}
