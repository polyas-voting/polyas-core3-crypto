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

import com.fasterxml.jackson.databind.ObjectMapper
import org.bouncycastle.util.encoders.Hex
import java.util.*
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class MessageTest {
    @Test
    fun `empty message`() {
        val msg = Message.fromHexString("")
        val b = msg.asBytes()
        assertEquals(0, msg.length())
        assertEquals(0, b.size)
        val hex = msg.asHexString()
        assertEquals(hex, "")
    }

    @Test
    fun `to and from hex`() {
        val hex = "ab0017cd00ef"

        val messageA = Message.fromHexString(hex.uppercase())
        val messageB = Message.fromHexString(hex.lowercase())

        assertEquals(messageA, messageB)
        assertEquals(6, messageA.length())
        assertEquals(hex, messageA.asHexString())
    }

    @Test
    fun `fromHex throws on incorrect input`() {
        assertFailsWith<Exception> { Message.fromHexString("123") }
    }

    @Test
    fun testSlice() {
        val bytes = byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
        val m = Message.fromBytes(bytes)
        assertContentEquals(m.asBytes(), bytes)

        val m37 = m.slice(3, 7)
        val b37 = byteArrayOf(3, 4, 5, 6)
        assertContentEquals(m37.asBytes(), b37)

        val m45 = m37.slice(1, 3)
        val b45 = byteArrayOf(4, 5)
        assertContentEquals(m45.asBytes(), b45)

        val m3x = m.slice(3)
        val b3x = byteArrayOf(3, 4, 5, 6, 7, 8, 9)
        assertContentEquals(m3x.asBytes(), b3x)

        assertFailsWith<IllegalArgumentException> { m.slice(-1, 3) }
        assertFailsWith<IllegalArgumentException> { m.slice(1, 99) }
    }

    @Test
    fun equality() {
        val m1 = Message.fromHexString("60afde34")
        val m2 = Message.fromHexString("60afde34")
        val mb = MessageConstructor(100)
        mb.put(0x60afde34)
        val m3 = mb.asMessage()
        val m4 = buildMessage { put(m1) }
        assertEquals(m1, m2)
        assertEquals(m2, m3)
        assertEquals(m1, m3)
        assertEquals(m1, m4)
        assertEquals(m1.hashCode().toLong(), m2.hashCode().toLong())
        assertEquals(m1.hashCode().toLong(), m3.hashCode().toLong())
        assertEquals(m1.hashCode().toLong(), m4.hashCode().toLong())
        val m5 = Message.fromHexString("60bfde34")
        val m6 = Message.fromHexString("60afde3434")
        mb.put(6)
        val m7 = mb.asMessage()
        assertEquals(m1, m3)
        assertNotEquals(m1, m5)
        assertNotEquals(m2, m6)
        assertNotEquals(m2, m6)
        assertNotEquals(m2, m7)
        val m8 = Message.fromHexString("1122334455667788")
        val m9 = Message.fromHexString("55667788")
        val destr = m8.destructor()
        destr.getInt()
        assertEquals(destr.getRest(), m9)
    }

    @Test
    fun base64() {
        val bytes = buildByteArray {
            put("abcdef")
            for (i in 0..100) put(i)
        }
        val message = Message.fromBytes(bytes)
        val base64encoded = Base64.getEncoder().encodeToString(bytes)

        assertEquals(base64encoded, message.asBase64())
    }


    @Test
    fun testCompare() {
        val a = Message.fromHexString("75aabc")
        val b = Message.fromHexString("75aabc01")
        val c = Message.fromHexString("75aabd")
        val d = Message.fromHexString("75abbc")
        val e = Message.fromHexString("b5aabc")
        assertTrue(Message.compare(a, b) < 0)
        assertTrue(Message.compare(b, c) < 0)
        assertTrue(Message.compare(c, d) < 0)
        assertTrue(Message.compare(d, e) < 0)
        assertTrue(Message.compare(a, c) < 0)
        assertTrue(Message.compare(a, d) < 0)
        assertTrue(Message.compare(a, e) < 0)
        assertTrue(Message.compare(e, b) > 0)
        assertEquals(0, Message.compare(e, e).toLong())
    }

    @Test
    fun testSerialisation() {
        val om = ObjectMapper()
        val message = Message.fromHexString("a0bcd7")
        val json = om.writeValueAsString(message)
        assertEquals(json, "\"a0bcd7\"")
        val o: Any = om.readValue(json, Message::class.java)
        assertEquals(message, o)
    }


    @Test
    fun `message builder`() {
        val message = buildMessage {
            put(Message.fromHexString("ffcc"))
            put(7)
        }

        assertEquals(Message.fromHexString("ffcc00000007"), message)
    }

    @Test
    fun `byte array builder`() {
        val b = buildByteArray {
            put(Message.fromHexString("ffcc"))
            put(7)
        }

        assertEquals(Message.fromHexString("ffcc00000007"), Message.fromBytes(b))
    }

    @Test
    fun `construct and destruct`() {
        // create a message from bytes
        val bytes = byteArrayOf(11, 22, 33, 44, 55, 66, 77, 88, 99)
        val a = Message.fromBytes(bytes)

        // and from a hex string
        val b = Message.fromHexString("88afa7de148897")

        // put those messages together
        val composed = buildMessage {
            put(a.length())
            put(a)
            put(b.length())
            put(b)
        }

        // get the content as bytes
        val data = composed.asBytes()
        // or as a hex string
        val hexStr = composed.asHexString()
        assertEquals(hexStr, Hex.toHexString(data))

        // decompose the composed message
        val destructor = composed.destructor()
        val lenFirst = destructor.getInt()
        val first = destructor.getMessage(lenFirst)
        val lenSecond = destructor.getInt()
        val second = destructor.getMessage(lenSecond)
        assertEquals(a, first)
        assertEquals(b, second)
        assertEquals(0, destructor.remainingLength().toLong())
    }

    @Test
    fun `more message constructing and destructing`() {
        val mb = MessageConstructor(100)
        val N = 1000
        for (i in 0 until N) {
            mb.put(i)
        }
        val m = mb.asMessage()
        assertEquals(m.length().toLong(), (4 * N).toLong())
        for (i in 0 until N) {
            mb.put(N + i)
        }
        val m1 = mb.asMessage()
        assertEquals(m1.length().toLong(), (2 * 4 * N).toLong())
        val d = m.destructor()
        val d1 = m1.destructor()
        for (i in 0 until N) {
            assertEquals(d.getInt().toLong(), i.toLong())
            assertEquals(d1.getInt().toLong(), i.toLong())
        }
        assertEquals(0, d.remainingLength().toLong())
        assertEquals(d1.remainingLength().toLong(), (4 * N).toLong())
        for (i in 0 until N) {
            assertEquals(d1.getInt().toLong(), (N + i).toLong())
        }

        val m2 = buildMessage(100) {
            for (i in 0 until N) {
                val auxmessage = buildMessage { put(i) }
                put(auxmessage)
                put(auxmessage.asBytes())
            }
        }

        val d2 = m2.destructor()
        for (i in 0 until N) {
            assertEquals(d2.getInt().toLong(), i.toLong())
            assertEquals(d2.getInt().toLong(), i.toLong())
        }
    }

    @Test
    fun `message and bytes builders are compatible`() {
        fun MessageConstructor.putContent() {
            for (i in 0 until 1000) {
                putShort(i.toShort())
                put(i)
                putByte(0)
                put("string-$i")
                putWithLength("another-string-$i")
            }
        }

        val message = buildMessage {
            putContent()
        }

        val bytes = buildByteArray {
            putContent()
        }

        assertEquals(message.asHexString(), Hex.toHexString(bytes))
    }
}
