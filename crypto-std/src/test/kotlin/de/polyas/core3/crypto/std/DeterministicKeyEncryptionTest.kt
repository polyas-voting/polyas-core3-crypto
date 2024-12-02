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
