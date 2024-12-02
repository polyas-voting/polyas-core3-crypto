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

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue
import de.polyas.core3.crypto.annotation.Doc
import org.bouncycastle.util.encoders.Hex
import java.nio.charset.StandardCharsets
import java.util.*
import kotlin.math.min

/**
 * An immutable sequence of bytes. It can be decomposed by slicing. It can
 * also be translated to/from arrays of bytes and hex-string.
 *
 * To build a message, use function [buildMessage].
 *
 * To deconstruct a message, use [Message.destructor]
 */
@Doc("Sequence of bytes represented as a hexadecimal string")
class Message internal constructor(
    private val buf: ByteArray,
    private val offset: Int,
    private val len: Int
) : Comparable<Message> {

    init {
        require (offset >= 0) { "offset must not be negative" }
        require (offset + len <= buf.size) { "offset + len must not exceed the buffer length" }
    }

    @JsonValue // this representation is used in Json serialization
    fun asHexString(): String = Hex.toHexString(asBytes())

    fun asBase64(): String = base64Encoder.encodeToString(asBytes())

    fun asUtf8String(): String = String(asBytes(), StandardCharsets.UTF_8)

    fun length(): Int = len

    fun asBytes(): ByteArray {
        val bytes = ByteArray(length())
        System.arraycopy(buf, offset, bytes, 0, length())
        return bytes
    }

    /**
     * Returns the slice of this message from [begin] to [end] (exclusively).
     *
     * The returned slice and this message share the same underlying byte array
     * (no data copying is involved).
     */
    fun slice(begin: Int, end: Int = len): Message =
        Message(buf, offset + begin, end - begin)

    /**
     * Returns a [MessageDestructor] which allows to decompose the content of this message.
     */
    fun destructor(): MessageDestructor = MessageDestructor(this)

    /**
     * Returns the underlying, raw byte array.
     */
    fun array(): ByteArray = buf

    /**
     * Return the offset with respect to the underlying raw byte array.
     */
    fun offset(): Int = offset

    override fun toString(): String = asHexString()

    override fun equals(other: Any?): Boolean {
        if (other !is Message) return false
        if (len != other.len) return false
        for (i in 0 until len) {
            if (buf[offset + i] != other.buf[other.offset + i]) return false
        }
        return true
    }

    override fun hashCode(): Int {
        var result = 1
        for (i in 0 until len) result = 31 * result + buf[offset + i]
        return result
    }

    override fun compareTo(other: Message): Int = compare(this, other)

    companion object {
        private val base64Decoder = Base64.getDecoder()
        private val base64Encoder = Base64.getEncoder()

        /**
         * Creates a message from a hex-encoded string.
         * May throw if the input is not in the expected format.
         */
       @JvmStatic @JsonCreator // used for JSON de-serialisation
        fun fromHexString(hexstr: String): Message {
            val bytes = Hex.decode(hexstr)
            return fromBytes(bytes)
        }

        /**
         * Creates a message from a UTF8 string.
         * May throw if the input is not in the expected format.
         */
        fun fromUTF8String(utf8String: String): Message =
            fromBytes(utf8String.toByteArray(StandardCharsets.UTF_8))

        /**
         * Creates a message from a base64-encoded string.
         * May throw if the input is not in the expected format.
         */
        fun fromBase64(base64String: String): Message =
            fromBytes(base64Decoder.decode(base64String))

        /**
         * Creates a message from the given byte array, by encapsulating this array.
         */
		fun fromBytes(bytes: ByteArray): Message =
		    Message(bytes, 0, bytes.size)

        /**
         * Generates a random message of the given [byteLength].
         */
        fun random(byteLength: Int): Message =
            SRNG.nextMessage(byteLength)

        /**
         * Compares two arrays w.r.t. the lexicographic order, where bytes are treated
         * as unsigned values.
         */
		fun compare(m1: Message, m2: Message): Int {
            val len1 = m1.length()
            val len2 = m2.length()
            val len = min(len1, len2)
            for (i in 0 until len) {
                val b1: Int = (m1.buf[m1.offset + i]).toInt() and 0xff
                val b2: Int = (m2.buf[m2.offset + i]).toInt() and 0xff
                if (b1 != b2) return b1 - b2
            }
            return len1 - len2
        }
    }
}

const val defaultInitialMessageSize: Int = 100

/**
 * A utility for constructing messages. It creates a new message and initializes it with the user-provide
 * [initBlock] function.
 *
 * The [initBlock] function can call `put` methods of  [MessageConstructor] (which it takes as a receiver):
 *
 * ```kotlin
 * val message = buildMessage {
 *     put(someBytes)
 *     put(anInteger)
 * }
 * ```
 */
inline fun buildMessage(initialSize: Int = defaultInitialMessageSize, initBlock: MessageConstructor.() -> Unit): Message {
    val builder = MessageConstructor(initialSize)
    builder.initBlock()
    return builder.asMessage()
}

/**
 * A utility for constructing byte arrays.
 *
 * A usage example:
 *
 * ```kotlin
 * val message = buildMessage {
 *     put(someBytes)
 *     put(anInteger)
 * }
 * ```
 */
inline fun buildByteArray(initialSize: Int = defaultInitialMessageSize, initBlock: MessageConstructor.() -> Unit): ByteArray {
    val builder = MessageConstructor(initialSize)
    builder.initBlock()
    return builder.asBytes()
}
