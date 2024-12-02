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
import java.nio.ByteBuffer
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets

/**
 * A utility for constructing messages.
 *
 * Typically, not created directly, but implicitly by function [buildMessage].
 *
 * @see Message
 */
class MessageConstructor(initialCapacity: Int) {

    private var buf: ByteBuffer = ByteBuffer.allocate(initialCapacity)

    fun length(): Int = buf.position()

    fun put(value: Int): MessageConstructor {
        ensureSpace(4)
        buf.putInt(value)
        return this
    }

    fun putShort(value: Short): MessageConstructor {
        ensureSpace(2)
        buf.putShort(value)
        return this
    }

    fun put(value: Long): MessageConstructor {
        ensureSpace(8)
        buf.putLong(value)
        return this
    }

    fun put(bytes: ByteArray?): MessageConstructor {
        if (bytes == null) {
            return this
        }
        ensureSpace(bytes.size)
        buf.put(bytes)
        return this
    }

    fun putByte(b: Byte): MessageConstructor {
        ensureSpace(1)
        buf.put(b)
        return this
    }

    fun put(bytes: ByteArray?, startIndex: Int): MessageConstructor {
        if (bytes == null) {
            return this
        }
        val n = bytes.size - startIndex
        ensureSpace(n)
        buf.put(bytes, startIndex, n)
        return this
    }

    fun put(bytes: ByteArray?, startIndex: Int, endIndexExclusive: Int): MessageConstructor {
        if (bytes == null) {
            return this
        }
        val n = endIndexExclusive - startIndex
        ensureSpace(n)
        buf.put(bytes, startIndex, n)
        return this
    }

    fun putWithLength(bytes: ByteArray): MessageConstructor {
        put(bytes.size)
        put(bytes)
        return this
    }

    fun putWithLength(string: String): MessageConstructor {
        val bytes = string.toByteArray(StandardCharsets.UTF_8)
        putWithLength(bytes)
        return this
    }

    fun put(message: Message?): MessageConstructor {
        if (message == null) {
            return this
        }
        ensureSpace(message.length())
        buf.put(message.array(), message.offset(), message.length())
        return this
    }

    fun put(str: String): MessageConstructor =
        put(str.toByteArray(StandardCharsets.UTF_8))

    fun put(str: String, charset: Charset?): MessageConstructor =
        put(str.toByteArray(charset!!))

    fun asBytes(): ByteArray {
        val newBuf = buf.duplicate()
        newBuf.flip()
        val buf = newBuf.array()
        val offset = newBuf.position()
        val len = newBuf.remaining()
        val bytes = ByteArray(len)
        System.arraycopy(buf, offset, bytes, 0, len)
        return bytes
    }

    fun asMessage(): Message {
        val newBuf = buf.duplicate()
        newBuf.flip()
        return Message(newBuf.array(), newBuf.position(), newBuf.remaining())
    }

    private fun ensureSpace(size: Int) {
        if (buf.remaining() < size) reallocate(size)
    }

    private fun reallocate(delta: Int) {
        val currentLenght = buf.position()
        val newSize = (currentLenght + delta) * 2
        val arr = ByteArray(newSize)
        buf.flip() // switch to the reading mode
        buf[arr, 0, currentLenght] // reads everything from buf to arr
        buf = ByteBuffer.wrap(arr)
        buf.position(currentLenght)
    }
}
