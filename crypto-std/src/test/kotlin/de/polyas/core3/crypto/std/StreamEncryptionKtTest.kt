package de.polyas.core3.crypto.std

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import kotlin.test.Test
import kotlin.test.assertEquals

class StreamEncryptionKtTest {

    @Test
    fun `fixed security parameters`() {
        // The implementation details of the stream encryption should not be changed unintentionally
        // as this may break dependent components.
        assertEquals(16, StreamEncryption.IV_LEN)
        assertEquals(256, StreamEncryption.KEY_BIT_SIZE)
    }

    @Test
    fun `encryption and decryption`() {
        val key = SymmetricKey.generate()
        val message = Message.fromHexString("fa00773311aafb")

        val ins = message.asBytes().inputStream()
        val outs = ByteArrayOutputStream()
        key.encryptStreamToStream(ins, outs)
        val encrypted = Message.fromBytes(outs.toByteArray())

        val encr = encrypted.asBytes().inputStream()
        val decr = ByteArrayOutputStream()
        key.decryptStreamToStream(encr, decr)
        val decrypted = Message.fromBytes(decr.toByteArray())
        assertEquals(message, decrypted)
    }

    @Test
    fun `ciphertext size`() {
        val key = SymmetricKey.generate()
        val message = Message.fromHexString("67") // one byte
        val ins = message.asBytes().inputStream()
        val outs = ByteArrayOutputStream()
        key.encryptStreamToStream(ins, outs)
        val encrypted = Message.fromBytes(outs.toByteArray())
        assertEquals(StreamEncryption.IV_LEN + 1, encrypted.length())
    }

    @Test
    fun `test encrypt and decrypt from stream`() {
        val key = SymmetricKey.generate()
        val message = "SymmetricEncryptionWorks"
        val ins = message.toByteArray().inputStream()
        val encryptedStream = ins.encrypt(key).readBytes()
        assertEquals(message.length+16, encryptedStream.size)
        val dec = encryptedStream.inputStream().decrypt(key).readBytes().toString(StandardCharsets.UTF_8)
        assertEquals(message, dec)
    }
}

