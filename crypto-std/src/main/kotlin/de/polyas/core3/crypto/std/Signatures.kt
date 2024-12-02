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
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

private const val DEFAULT_KEY_SIZE = 3072
private val keyFactory = KeyFactory.getInstance("RSA")

/**
 * A key pair for RSA signing/verification.
 */
data class SigningKeyPair(
    val verificationKey: VerificationKey,
    val signingKey: SigningKey
) {
    companion object {
        /**
         * Generates a random signing/verification key pair.
         */
        fun generate(keySize: Int = DEFAULT_KEY_SIZE): SigningKeyPair {
            val keyPairGen = KeyPairGenerator.getInstance("RSA")
            keyPairGen.initialize(keySize)
            val pair = keyPairGen.generateKeyPair()
            return SigningKeyPair(VerificationKey(pair.public.encoded), SigningKey(pair.private.encoded))
        }
    }
}

/**
 * Verification key for RSA-based signatures (SHA256withRSA).
 */
class VerificationKey(private val publicKeyBytes: ByteArray) {

    private val publicKey: PublicKey = keyFactory.generatePublic(X509EncodedKeySpec(publicKeyBytes))

    companion object {
        @JsonCreator @JvmStatic
        fun fromHexString(hexString: String) = fromMessage(Message.fromHexString(hexString))

        fun fromMessage(message: Message) = VerificationKey(message.asBytes())
    }

    @JsonValue
    fun asHexString(): String = asMessage().asHexString()

    fun asMessage(): Message = Message.fromBytes(publicKeyBytes)

    /**
     * Verifies the given [signature] on the given [message] using this verification key.
     */
    fun verify(signature: Message, message: Message): SignatureVerificationResult {
        return try {
            val sig: Signature = Signature.getInstance("SHA256withRSA")
            sig.initVerify(publicKey)
            sig.update(message.array(), message.offset(), message.length())
            when (sig.verify(signature.array(), signature.offset(), signature.length())) {
                true -> SignatureVerificationResult.OK
                false -> SignatureVerificationResult.Invalid
            }
        } catch (ex: GeneralSecurityException) {
            SignatureVerificationResult.Error(ex)
        }
    }

    override fun equals(other: Any?): Boolean =
        (other is VerificationKey) && (publicKey == other.publicKey)

    override fun hashCode(): Int =
        publicKeyBytes.contentHashCode()
}

/**
 * Signing key for RSA-based signatures (SHA256withRSA).
 */
class SigningKey(
    private val privateKeyBytes: ByteArray
) {
    private val privateKey: PrivateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(privateKeyBytes))

    companion object {
        @JsonCreator @JvmStatic
        fun fromHexString(hexString: String) = fromMessage(Message.fromHexString(hexString))

        fun fromMessage(keyAsMessage: Message) = SigningKey(keyAsMessage.asBytes())
    }

    fun getBytes(): ByteArray = privateKeyBytes

    @JsonValue
    fun asMessage(): Message =
        Message.fromBytes(privateKeyBytes)

    /**
     * Signs the given [message] with this signing key.
     */
    fun sign(message: Message): Message {
        val signer: Signature = Signature.getInstance("SHA256withRSA")
        signer.initSign(privateKey)
        signer.update(message.array(), message.offset(), message.length())
        return Message.fromBytes(signer.sign())
    }

    override fun equals(other: Any?): Boolean =
        (other is SigningKey) && (privateKey == other.privateKey)

    override fun hashCode(): Int =
        privateKeyBytes.contentHashCode()
}

sealed interface SignatureVerificationResult {
    data object OK: SignatureVerificationResult
    data object Invalid: SignatureVerificationResult
    data class Error(val exception: Exception): SignatureVerificationResult

    fun isOk() = this is OK
}

