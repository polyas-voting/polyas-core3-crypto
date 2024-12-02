package de.polyas.core3.crypto.std

import java.nio.ByteBuffer

/**
 * A utility for deconstructing messages. The `get*` methods consume the message starting
 * from the beginning.
 */
class MessageDestructor(message: Message) {

    private val buffer: ByteBuffer = ByteBuffer.wrap(message.array(), message.offset(), message.length())

    fun remainingLength(): Int = buffer.remaining()

    fun getMessage(len: Int): Message {
        require (len <= buffer.limit() - buffer.position())
        val msg = Message(buffer.array(), buffer.position(), len)
        moveForward(len)
        return msg
    }

    fun getInt(): Int = buffer.int

    fun getRest(): Message = getMessage(remainingLength())

    private fun moveForward(bytesToSkip: Int) {
        require(bytesToSkip <= remainingLength()) { "Value too big for buffer" }
        buffer.position(buffer.position() + bytesToSkip)
    }
}