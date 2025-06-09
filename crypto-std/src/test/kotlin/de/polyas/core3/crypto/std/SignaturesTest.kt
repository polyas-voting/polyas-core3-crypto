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

class SignaturesTest {
    @Test
    fun `signing-verifying`() {
        val message = SRNG.nextMessage(400)
        val keyPair = SigningKeyPair.generate()
        val signature = keyPair.signingKey.sign(message)
        assertEquals(SignatureVerificationResult.OK, keyPair.verificationKey.verify(signature, message))
    }

    @Test
    fun `wrong signature is rejected`() {
        val message = SRNG.nextMessage(400)
        val falseSignature = SRNG.nextMessage(384)
        val keyPair = SigningKeyPair.generate()
        assertEquals(SignatureVerificationResult.Invalid, keyPair.verificationKey.verify(falseSignature, message))
    }

    @Test
    fun testSerialization() {
        val message = SRNG.nextMessage(400)
        val keyPair = SigningKeyPair.generate()
        val signature = keyPair.signingKey.sign(message)

        val json = om.writeValueAsString(keyPair)
        val deserialized = om.readValue(json, SigningKeyPair::class.java)

        assertEquals(SignatureVerificationResult.OK, deserialized.verificationKey.verify(signature, message))
    }

    companion object {
        private val om: ObjectMapper = jacksonObjectMapper().apply {
            enable(SerializationFeature.INDENT_OUTPUT)
        }
    }
}
