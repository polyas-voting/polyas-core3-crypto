package de.polyas.core3.crypto.std

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class SymmetricKeyTest {
    private val key = SymmetricKey.generate()

    @Test
    fun `encryption-decryption`() {
        val plaintext = GuarderSRNG.nextMessage(10000)
        val encrypted = key.encrypt(plaintext)
        val decrypted = key.decrypt(encrypted).getOrThrow()
        assertEquals(plaintext, decrypted)
    }

    @Test
    fun `deterministic encryption-decryption`() {
        val plaintext = GuarderSRNG.nextMessage(10000)
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