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
