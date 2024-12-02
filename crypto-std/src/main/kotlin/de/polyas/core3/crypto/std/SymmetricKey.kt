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

import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * A class encapsulating a symmetric key and offering encryption and decryption functions.
 *
 * It uses the AES algorithm in the GCM mode.
 */
class SymmetricKey {
    private val key: SecretKey
    private val keyBytes: ByteArray

    constructor(bytes: ByteArray) {
        keyBytes = bytes
        key = SecretKeySpec(keyBytes, KEY_ALG)
    }

    constructor(secKey: SecretKey) {
        require(secKey.algorithm == KEY_ALG) { "The algorithm type must be AES" }
        key = secKey
        keyBytes = key.encoded
    }

    constructor(keyMessage: Message) : this(keyMessage.asBytes())

    fun asMessage(): Message =
        Message.fromBytes(keyBytes)

    /**
     * Encrypts the given [plaintext] with this key. A random initialisation vector
     * (of size [IV_LEN]) is used and  included in the initial part of the result message.
     */
    fun encrypt(plaintext: Message): Message {
        val iv = Message.random(IV_LEN)
        return encrypt(plaintext, iv)
    }

    /**
     * Encrypts the given [plaintext] using explicitly given initialisation vector.
     * The initialisation vector is include in the returned message (as the first part of it).
     */
    fun encrypt(plaintext: Message, iv: Message): Message {
        return buildMessage {
            put(iv)
            put(justEncrypt(plaintext, iv))
        }
    }

    /**
     * Deterministically encrypts the given [plaintext] with this key,
     * using the zero initialisation vector.
     */
    fun deterministicEncryption(plaintext: Message): Message =
        justEncrypt(plaintext, Message.fromBytes(zeroIv))

    /**
     * Decrypts the given [ciphertext] with this key. It assumes that the initialisation
     * vector is included in the initial part of the [ciphertext].
     *
     * Note that this operation is expected to fail (with an exception encapsulated in the returned [Result])
     * whenever the [ciphertext] is invalid (when it is not the result of encryption with the corresponding key).
     */
    fun decrypt(ciphertext: Message): Result<Message> {
        require (ciphertext.length() >= IV_LEN) { "Message too short to contain an IV" }
        val destructor = ciphertext.destructor()
        val ivMsg = destructor.getMessage(IV_LEN)
        return decrypt(destructor.getRest(), ivMsg)
    }

    /**
     * Decrypts the given [ciphertext] with this key, using the zeros initialisation vector.
     *
     * Note that this operation is expected to fail (with an exception encapsulated in the returned [Result])
     * whenever the [ciphertext] is invalid (when it is not the result of encryption with the corresponding key).
     */
    fun deterministicDecryption(ciphertext: Message): Result<Message> =
        decrypt(ciphertext, zeroIvMsg)

    private fun decrypt(ciphertext: Message, ivMsg: Message): Result<Message> = runCatching {
        require (ivMsg.length() == IV_LEN)
        val iv = GCMParameterSpec(GCM_TAG_LENGTH * 8, ivMsg.array(), ivMsg.offset(), ivMsg.length())
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key, iv)
        Message.fromBytes(c.doFinal(ciphertext.array(), ciphertext.offset(), ciphertext.length()))
    }

    /**
     * Encrypts the given [plaintext] using the initialisation vector [iv] without
     * adding the initialisation vector to the returned message.
     */
    private fun justEncrypt(plaintext: Message, iv: Message): Message {
        require (iv.length() == IV_LEN)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv.array(), iv.offset(), iv.length())
        c.init(Cipher.ENCRYPT_MODE, key, spec)
        return Message.fromBytes(c.doFinal(plaintext.array(), plaintext.offset(), plaintext.length()))
    }

    fun underlyingKey(): SecretKey = key

    companion object {
        const val GCM_TAG_LENGTH = 16 // in bytes
        const val KEY_SIZE = 256
        const val IV_LEN = 12 // = 96-bit

        private const val KEY_ALG = "AES"
        private val zeroIv = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        private val zeroIvMsg = Message.fromBytes(zeroIv)

        /**
         * Generates a random key
         */
		fun generate(): SymmetricKey {
            val kgen = KeyGenerator.getInstance(KEY_ALG)
            kgen.init(KEY_SIZE)
            val secKey = kgen.generateKey()
            return SymmetricKey(secKey)
        }
    }
}
