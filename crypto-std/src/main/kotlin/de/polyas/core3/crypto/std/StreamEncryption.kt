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

import java.io.*
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

object StreamEncryption {

    /** The length of the initialisation vector used for the stream encryption in bytes */
    const val IV_LEN = 16

    /** The length of the AES key used for the stream encryption in bits */
    const val KEY_BIT_SIZE = SymmetricKey.KEY_SIZE
}

/**
 * Encrypts the content of the given [inputStream] using this symmetric key (given as the receiver)
 * and copies the encrypted content to the [outputStream].
 *
 * **Note:** Uses an unauthenticated encryption scheme (AES in the CTR mode).
 *
 * **Note:** Does not close any of the given streams.
 *
 * Throws on failures.
 */
fun SymmetricKey.encryptStreamToStream(inputStream: InputStream, outputStream: OutputStream) {
    this.underlyingKey().encryptStreamToStream(inputStream, outputStream)
}

/**
 * Encrypts the content of the [inputStream] using this secret key (given as the receiver)
 * and copies the encrypted content to the [outputStream].
 *
 * **Note:** Uses an unauthenticated encryption scheme (AES in the CTR mode).
 *
 * **Note:** Does not close any of the given streams.
 *
 * Throws on failures.
 */
fun SecretKey.encryptStreamToStream(inputStream: InputStream, outputStream: OutputStream) {
    val iv = ByteArray(StreamEncryption.IV_LEN)
    SRNG.nextBytes(iv)
    val c = Cipher.getInstance("AES/CTR/NoPadding")
    val spec = IvParameterSpec(iv)
    c.init(Cipher.ENCRYPT_MODE, this, spec)
    outputStream.write(iv)
    val cipherIn = CipherInputStream(inputStream, c)
    cipherIn.copyTo(outputStream)
}

/**
 * Encrypts the receiver using the symmetric key
 * and delivers an InputStream
 *
 * **Note:** Uses an unauthenticated encryption scheme (AES in the CTR mode).
 *
 * **Note:** Does not close any of the given streams.
 *
 * Throws on failures.
 */
fun InputStream.encrypt(key: SymmetricKey): InputStream =
    encrypt(key.underlyingKey())

/**
 * Encrypts the receiver using the secret key
 * and delivers an InputStream
 *
 * **Note:** Uses an unauthenticated encryption scheme (AES in the CTR mode).
 *
 * **Note:** Does not close any of the given streams.
 *
 * Throws on failures.
 */
fun InputStream.encrypt(key: SecretKey): InputStream {

    // NOTE: some client implementations fail on input stream with unknown size.
    // We use therefore FileInputStreams, because they know their length.
    fun saveAsTempFile(inStream: InputStream): InputStream {
        val file = File.createTempFile("temp", ".tmp")
        file.deleteOnExit()
        file.outputStream().use { outStream ->
            inStream.copyTo(outStream)
        }
        return object : FilterInputStream(file.inputStream()) {
            override fun close() {
                try {
                    super.close()
                } finally {
                    file.delete()
                }
            }
        }
    }

    val iv = ByteArray(StreamEncryption.IV_LEN)
    SRNG.nextBytes(iv)
    val c = Cipher.getInstance("AES/CTR/NoPadding")
    val spec = IvParameterSpec(iv)
    c.init(Cipher.ENCRYPT_MODE, key, spec)
    CipherInputStream(this, c).use { encryptedStream ->
        SequenceInputStream(iv.inputStream(), encryptedStream).use { encryptedWithIV ->
            return saveAsTempFile(encryptedWithIV)
        }
    }
}

/**
 * Decrypts the content of the [inputStream] using this symmetric key (given as the receiver)
 * and copies the decrypted content to the [outputStream].
 *
 * **Note:** Uses an unauthenticated encryption scheme (AES in the CTR mode).
 *
 * **Note:** Does not close any of the given streams.
 *
 * Throws on failures.
 */
fun SymmetricKey.decryptStreamToStream(inputStream: InputStream, outputStream: OutputStream) {
    this.underlyingKey().decryptStreamToStream(inputStream, outputStream)
}

/**
 * Decrypts the content of the [inputStream] using this secret key (given as the receiver)
 * and copies the decrypted content to the [outputStream].
 *
 * **Note:** Uses an unauthenticated encryption scheme (AES in the CTR mode).
 *
 * **Note:** Does not close any of the given streams.
 *
 * Throws on failures.
 */
fun SecretKey.decryptStreamToStream(inputStream: InputStream, outputStream: OutputStream) {
    val cipherIn = inputStream.decrypt(this)
    cipherIn.copyTo(outputStream)
}

/**
 * Decrypts the content of this input stream using the given secret [key]
 * and returns the decrypted (input) stream.
 *
 * **Note:** Uses an unauthenticated encryption scheme (AES in the CTR mode).
 *
 * **Note:** Does not close this stream.
 */
fun InputStream.decrypt(key: SymmetricKey): InputStream =
    this.decrypt(key.underlyingKey())

/**
 * Decrypts the content of this input stream using the given secret [key]
 * and returns the decrypted (input) stream.
 *
 * **Note:** Uses an unauthenticated encryption scheme (AES in the CTR mode).
 *
 * **Note:** Does not close this stream.
 */
fun InputStream.decrypt(key: SecretKey): InputStream {
    val iv = ByteArray(StreamEncryption.IV_LEN)
    this.read(iv)
    val spec = IvParameterSpec(iv)
    val c = Cipher.getInstance("AES/CTR/NoPadding")
    c.init(Cipher.DECRYPT_MODE, key, spec)
    return CipherInputStream(this, c).buffered()
}
