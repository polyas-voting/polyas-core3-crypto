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
import kotlin.test.*

class SRNGTest {

    @Test
    fun `sampling bytes`() {
        val bytes1 = SRNG.nextBytes(1000)
        val bytes2 = SRNG.nextBytes(1000)

        assertEquals(1000, bytes1.size)
        assertFalse(bytes1 contentEquals bytes2)
    }

    @Test
    fun `sampling messages`() {
        val message1 = SRNG.nextMessage(1000)
        val message2 = SRNG.nextMessage(1000)

        assertEquals(1000, message1.length())
        assertNotEquals(message1, message2)
    }

    @Test
    fun `sampled big integers are in the expected range`() {
        val upperBound = BigInteger.valueOf(710000000000000)

        repeat (1000) {
            val sampled = SRNG.nextBigInt(upperBound)
            assertTrue(sampled >= BigInteger.ZERO)
            assertTrue(sampled < upperBound)
        }
    }

    @Test
    fun `sampled big integers in range are in the expected range`() {
        val lowerBound = BigInteger.valueOf(700000000000000)
        val upperBound = BigInteger.valueOf(710000000000000)

        repeat (1000) {
            val sampled = SRNG.nextBigIntInRange(lowerBound, upperBound)
            assertTrue(sampled >= lowerBound)
            assertTrue(sampled < upperBound)
        }
    }

    @Test
    fun `begin and end counters`() {
        val end1 = SRNG.endCount()
        val begin1 = SRNG.beginCount()
        assertTrue(begin1 >= end1)

        SRNG.nextMessage(1000)
        val end2 = SRNG.endCount()
        val begin2 = SRNG.beginCount()
        assertTrue(begin2 >= end2)
        assertTrue(begin1 <= begin2) // one might expect the difference to be 1, but it can be bigger if tests run in parallel
        assertTrue(end1 <= end2)
    }


    @Test
    fun `begin and end counters inside use`() {
        SRNG.use {
            val end = SRNG.endCount()
            val begin = SRNG.beginCount()
            assertTrue(begin > end)
        }
    }

    @Test
    fun `foo sampling bytes`() {
        val upperBound = BigInteger.valueOf(710000000000000)
        data class Event(val modulus: BigInteger, val value: BigInteger)
        val events = mutableListOf<Event>()
        val myInterceptor = object : SRNG.Interceptor {
            override fun bytes(bytes: ByteArray) { }
            override fun other() { }
            override fun bi(modulus: BigInteger, value: BigInteger) {
                events += Event(modulus, value)
            }
        }

        SRNG.setInterceptor(myInterceptor)
        val sampled = SRNG.nextBigInt(upperBound)
        SRNG.resetInterceptor()

        val expectedEvent = Event(upperBound, sampled)
        assertTrue(expectedEvent in events)
    }
}
