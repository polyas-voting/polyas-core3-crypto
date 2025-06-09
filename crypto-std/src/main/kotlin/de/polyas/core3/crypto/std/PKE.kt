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

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue
import de.polyas.core3.crypto.annotation.Doc
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

private const val DEFAULT_KEY_SIZE = 2048
private val keyFactory = KeyFactory.getInstance("RSA")

@Doc("A key pair for RSA encryption/decryption")
data class EncryptionKeyPair(
    @Doc("An encryption (public) key")
    val encryptionKey: EncryptionKey,

    @Doc("A decryption (private) key")
    val decryptionKey: DecryptionKey
) {
    companion object {
        /**
         * Generates a random asymmetric key pair.
         */
        fun generate(keySize: Int = DEFAULT_KEY_SIZE): EncryptionKeyPair {
            val keyPairGen = KeyPairGenerator.getInstance("RSA")
            keyPairGen.initialize(keySize)
            val pair = keyPairGen.generateKeyPair()
            val privateKey = DecryptionKey(pair.private.encoded)
            val publicKey = EncryptionKey(pair.public.encoded)
            return EncryptionKeyPair(publicKey, privateKey)
        }
    }
}

@Doc("RSA public (encryption) key for the following encryption/decryption scheme: RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
class EncryptionKey(private val keyAsBytes: ByteArray) {

    private val publicKey: PublicKey = keyFactory.generatePublic(X509EncodedKeySpec(keyAsBytes))

    companion object {
        @JsonCreator @JvmStatic
        fun fromHexString(keyAsHexString: String) = fromMessage(Message.fromHexString(keyAsHexString))

        fun fromMessage(keyAsMessage: Message) = EncryptionKey(keyAsMessage.asBytes())
    }

    @JsonValue
    fun asHexString(): String = asMessage().asHexString()

    override fun toString(): String = asHexString()

    fun asMessage(): Message = Message.fromBytes(keyAsBytes)

    /**
     * Encrypts the given [plaintext] with this encryption key.
     *
     * The plaintext length is bounded, in the current implementation, to 190 bytes.
     * For encrypting messages of unbounded lengths, see [hybridEnc].
     */
    fun encrypt(plaintext: Message): Message {
        val c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        c.init(Cipher.ENCRYPT_MODE, publicKey)
        val out = c.doFinal(plaintext.array(), plaintext.offset(), plaintext.length())
        return Message.fromBytes(out)
    }

    /**
     * Encrypts the given [plaintext] with this encryption key, using hybrid encryption.
     * The [plaintext] can be of arbitrary length.
     */
    fun hybridEnc(plaintext: Message): Message {
        val symmetricKey = SymmetricKey.generate()
        val encryptedKey = encrypt(symmetricKey.asMessage())
        val encryptedMessage = symmetricKey.deterministicEncryption(plaintext)

        return buildMessage(initialSize = 4 + encryptedKey.length() + encryptedMessage.length()) {
            put(encryptedKey.length())
            put(encryptedKey)
            put(encryptedMessage)
        }
    }

    override fun equals(other: Any?): Boolean =
        (other is EncryptionKey) && publicKey == other.publicKey

    override fun hashCode(): Int =
        keyAsBytes.contentHashCode()
}

@Doc("RSA decryption (private) key for the following encryption/decryption scheme: RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
class DecryptionKey(private val keyAsBytes: ByteArray) {

    private val privateKey: PrivateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyAsBytes))

    companion object {
        @JsonCreator @JvmStatic
        fun fromHexString(hexString: String) = fromMessage(Message.fromHexString(hexString))

        fun fromMessage(message: Message) = DecryptionKey(message.asBytes())
    }

    @JsonValue
    fun asHexString(): String = asMessage().asHexString()

    fun asMessage(): Message = Message.fromBytes(keyAsBytes)

    /**
     * Decrypts the given [ciphertext] with this decryption key.
     *
     * Note that this operation is expected to fail (with an exception encapsulated in the returned [Result])
     * whenever the [ciphertext] is invalid (when it is not the result of encryption with the corresponding key).
     */
    fun decrypt(ciphertext: Message): Result<Message> = runCatching {
        val c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        c.init(Cipher.DECRYPT_MODE, privateKey)
        val resultBytes = c.doFinal(ciphertext.array(), ciphertext.offset(), ciphertext.length())
        Message.fromBytes(resultBytes)
    }

    /**
     * Decrypts the given [ciphertext] with this decryption key, where the ciphertext has been
     * encrypted using hybrid encryption (supporting plaintexts of arbitrary size).
     *
     * Note that this operation is expected to fail (with an exception encapsulated in the returned [Result])
     * whenever the [ciphertext] is invalid (when it is not the result of encryption with the corresponding key).
     */
    fun hybridDec(ciphertext: Message): Result<Message> = runCatching {
        val destructor = ciphertext.destructor()
        val encryptedKeyLen = destructor.getInt()
        val encryptedKey = destructor.getMessage(encryptedKeyLen)
        val decrypt = decrypt(encryptedKey).getOrElse { return Result.failure(it) }
        val symmetricKey = SymmetricKey(decrypt)
        return symmetricKey.deterministicDecryption(destructor.getRest())
    }

    override fun equals(other: Any?): Boolean =
        (other is DecryptionKey) && (keyAsBytes.contentEquals(other.keyAsBytes))

    override fun hashCode(): Int =
        keyAsBytes.contentHashCode()
}
