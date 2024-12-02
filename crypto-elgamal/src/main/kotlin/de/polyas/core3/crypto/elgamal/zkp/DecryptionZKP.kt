/*
 * Copyright 2025 Polyas GmbH
 *
 * Licensed under GNU Affero General Public License v3.0; you may not use
 * this file except in compliance with the License. You may obtain a copy of
 * the License at https://www.gnu.org/licenses/agpl-3.0.en.html.
 * This software is distributed WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
 * either express or implied.
 */
package de.polyas.core3.crypto.elgamal.zkp

import de.polyas.core3.crypto.elgamal.Ciphertext
import de.polyas.core3.crypto.elgamal.CyclicGroup
import de.polyas.core3.crypto.elgamal.VerificationResult
import de.polyas.core3.crypto.annotation.Doc
import java.math.BigInteger

/**
 * Utility for creation and validation of non-interactive zero-knowledge proofs
 * of correct decryption over the given cyclic [group].
 */
class DecryptionZKP<GroupElem>(private val group: CyclicGroup<GroupElem>, private val publicKey: GroupElem) {

    @Doc("A non-interactive zero-knowledge proof of correct decryption")
    data class Proof<GroupElem>(
        val decryptionShare: GroupElem,
        val eqlogZKP: EqlogNIZKP.Proof
    )

    @Doc("A decrypted message along with a zero-knowledge proof of correct decryption")
    data class DecryptionWithProof<GroupElem>(
        @property:Doc("The decrypted message")
        val plaintext: BigInteger,

        @property:Doc("Zero-knowledge proof of correct decryption")
        val proof: Proof<GroupElem>
    )

    /**
     * Decrypts the given [ciphertext] and produces a zero-knowledge proof for this decryption.
     */
    fun decryptAndProve(ciphertext: Ciphertext<GroupElem>, privateKey: BigInteger) : DecryptionWithProof<GroupElem> {
        val proof = createProof(ciphertext, privateKey)
        val plaintext = applyDecryptionFactor(ciphertext, proof.decryptionShare)
        return DecryptionWithProof(plaintext, proof)
    }

    /**
     * Checks the given zero-knowledge [proof] showing that the given [ciphertext] decrypts to [plaintext].
     */
    fun verify(ciphertext: Ciphertext<GroupElem>, plaintext: BigInteger, proof: Proof<GroupElem>): VerificationResult {
        verifyZkpOnly(ciphertext, proof) onFailure { return it }
        return if (applyDecryptionFactor(ciphertext, proof.decryptionShare) == plaintext) VerificationResult.Correct
               else VerificationResult.Failed("The included decryption share does not yield the included plaintext")
    }

    /**
     * Checks the underlying ZKP the equality of discrete logarithms, without checking the plaintext itself.
     */
    fun verifyZkpOnly(ciphertext: Ciphertext<GroupElem>, proof: Proof<GroupElem>): VerificationResult =
        EqlogNIZKP(group).verify(
            statement = EqlogZKP.Statement(group.generator, ciphertext.x, publicKey, proof.decryptionShare),
            proof = proof.eqlogZKP
        )

    /**
     * Applies the decryption factor to the ciphertext to obtain the decrypted (plaintext) message.
     */
    fun applyDecryptionFactor(ciphertext: Ciphertext<GroupElem>, decryptionFactor: GroupElem): BigInteger =
        with (group) {
            val encodedPlaintext = ciphertext.y / decryptionFactor
            group.decode(encodedPlaintext)
        }

    private fun createProof(ciphertext: Ciphertext<GroupElem>, privateKey: BigInteger): Proof<GroupElem> =
        with (group) {
            val decryptionFactor = ciphertext.x pow privateKey
            val eqlogStatement = EqlogZKP.Statement(generator, ciphertext.x, publicKey, decryptionFactor)
            val eqlogNIZKP = EqlogNIZKP(group)
            val eqlogZKP = eqlogNIZKP.createProof(eqlogStatement, privateKey)
            Proof(decryptionFactor, eqlogZKP)
        }
}
