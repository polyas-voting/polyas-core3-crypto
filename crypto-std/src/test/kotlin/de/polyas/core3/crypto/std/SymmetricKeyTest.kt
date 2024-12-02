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

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class SymmetricKeyTest {
    private val key = SymmetricKey.generate()

    @Test
    fun `encryption-decryption`() {
        val plaintext = Message.random(10000)
        val encrypted = key.encrypt(plaintext)
        val decrypted = key.decrypt(encrypted).getOrThrow()
        assertEquals(plaintext, decrypted)
    }

    @Test
    fun `encryption with explicit IV`() {
        val plaintext = Message.random(10000)
        val iv = Message.random(SymmetricKey.IV_LEN)
        val encrypted = key.encrypt(plaintext, iv)
        val decrypted = key.decrypt(encrypted).getOrThrow()
        assertEquals(plaintext, decrypted)

        val initial = encrypted.slice(0, SymmetricKey.IV_LEN)
        assertEquals(iv, initial)
    }

    @Test
    fun `deterministic encryption-decryption`() {
        val plaintext = Message.random(10000)
        val encrypted = key.deterministicEncryption(plaintext)
        val decrypted = key.deterministicDecryption(encrypted).getOrThrow()
        assertEquals(plaintext, decrypted)
    }

    @Test
    fun `deterministic encryption is not deterministic`() {
        val plaintext = Message.fromUTF8String("abcoijoijoijoijoi*(&**(123187yoijfsd!")
        val encrypted1 = key.encrypt(plaintext)
        val encrypted2 = key.encrypt(plaintext)
        assertNotEquals(encrypted1, encrypted2)
    }

    @Test
    fun `deterministic encryption is deterministic`() {
        val plaintext = Message.fromUTF8String("abcoijoijoijoijoi*(&**(123187yoijfsd!")
        val encrypted1 = key.deterministicEncryption(plaintext)
        val encrypted2 = key.deterministicEncryption(plaintext)
        assertEquals(encrypted1, encrypted2)
    }

    @Test
    fun `key to and from message`() {
        val keyAsMessage = key.asMessage()
        val keyFromMessage = SymmetricKey(keyAsMessage)
        val plaintext = Message.fromUTF8String("abcoijoijoijoijoi*(&**(123187yoijfsd!")

        val encrypted = key.encrypt(plaintext)
        val decrypted = keyFromMessage.decrypt(encrypted).getOrThrow()
        assertEquals(plaintext, decrypted)
    }

    @Test
    fun `decryption fails on an incorrect ciphertext`() {
        val ciphertext = Message.fromUTF8String("this is not a valid ciphertext")
        val result = key.decrypt(ciphertext)
        assertTrue(result.isFailure)
    }
}
