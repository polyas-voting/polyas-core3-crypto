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

class DeterministicKeyEncryptionTest {
    private val enc = DeterministicKeyEncryption(SymmetricKey.generate())

    @Test
    fun `encryption-decryption works`() {
        val key = Message.fromUTF8String("Abc®©".repeat(100))
        val encrypted = enc.encrypt(key)
        val decrypted = enc.decrypt(encrypted).getOrThrow()
        assertEquals(key, decrypted)
    }

    @Test
    fun `encryption is deterministic`() {
        val key = Message.fromUTF8String("Abc®©".repeat(100))
        val enc1 = enc.encrypt(key)
        val enc2 = enc.encrypt(key)
        assertEquals(enc1, enc2)
    }
}
