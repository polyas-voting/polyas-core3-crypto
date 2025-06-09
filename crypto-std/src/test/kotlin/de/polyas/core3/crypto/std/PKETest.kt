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
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PKETest {
    @Test
    fun `encryption-decryption`() {
        val plaintext = SRNG.nextMessage(8)
        val keyPair = EncryptionKeyPair.generate()
        val encrypted = keyPair.encryptionKey.encrypt(plaintext)
        val decrypted = keyPair.decryptionKey.decrypt(encrypted).getOrThrow()
        assertEquals(plaintext, decrypted)
    }

    @Test
    fun `hybrid encryption-decryption`() {
        val plaintext = SRNG.nextMessage(1000000)
        val keyPair = EncryptionKeyPair.generate()
        val encrypted = keyPair.encryptionKey.hybridEnc(plaintext)
        val decrypted = keyPair.decryptionKey.hybridDec(encrypted).getOrThrow()
        assertEquals(plaintext, decrypted)
    }

    @Test
    fun testSerialisation() {
        val keys = EncryptionKeyPair.generate()
        val keyPairJson = om.writeValueAsString(keys)
        om.readValue(keyPairJson, EncryptionKeyPair::class.java)
    }

    @Test
    fun `encryption fails on invalid ciphertext`() {
        val keyPair = EncryptionKeyPair.generate()
        val ciphertext = Message.fromUTF8String("This is not a valid ciphertext")
        val result = keyPair.decryptionKey.decrypt(ciphertext)
        assertTrue(result.isFailure)
    }

    @Test
    fun `hybrid encryption fails on invalid ciphertext`() {
        val plaintext = SRNG.nextMessage(1000000)
        val keyPair = EncryptionKeyPair.generate()
        val encrypted = keyPair.encryptionKey.hybridEnc(plaintext)
        val invalidCiphertext = buildMessage { put(encrypted); putByte(23) }
        val result = keyPair.decryptionKey.hybridDec(invalidCiphertext)
        assertTrue(result.isFailure)
    }

    companion object {
        private val om: ObjectMapper = jacksonObjectMapper().apply {
            enable(SerializationFeature.INDENT_OUTPUT)
        }
    }
}
