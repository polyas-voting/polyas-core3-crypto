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

import com.fasterxml.jackson.annotation.JsonProperty
import de.polyas.core3.crypto.elgamal.CyclicGroup
import de.polyas.core3.crypto.elgamal.VerificationResult
import de.polyas.core3.crypto.elgamal.zkp.EqlogZKP.InteractiveProver
import de.polyas.core3.crypto.std.uniformHash
import de.polyas.core3.crypto.annotation.Doc
import java.math.BigInteger

/**
 * Non-interactive zero-knowledge proof of equality of discrete logarithms.
 *
 * @see EqlogZKP
 */
class EqlogNIZKP<GroupElement>(val group: CyclicGroup<GroupElement>) {

    @Doc("Non-interactive zero-knowledge proof of equality of discrete logarithms")
    data class Proof(
        @get:JsonProperty("c") val c: BigInteger,
        @get:JsonProperty("f") val f: BigInteger
    )

    fun createProof(statement: EqlogZKP.Statement<GroupElement>, witness: BigInteger): Proof {
        val prover = InteractiveProver(group, statement, witness)
        val initialMessage = prover.initialMessage
        val challenge = challenge(statement, initialMessage.A, initialMessage.B)
        val finalMessage = prover.finalMessage(challenge)
        return Proof(challenge, finalMessage)
    }

    fun verify(statement: EqlogZKP.Statement<GroupElement>, proof: Proof): VerificationResult =
        with(group) {
            val expectedA = (statement.baseX pow proof.f) / (statement.X pow proof.c)
            val expectedB = (statement.baseY pow proof.f) / (statement.Y pow proof.c)

            when (challenge(statement, expectedA, expectedB)) {
                proof.c -> VerificationResult.Correct
                else -> VerificationResult.Failed("The NIZKP of equality of discrete logarithms is incorrect")
            }
        }

    private fun challenge(statement: EqlogZKP.Statement<GroupElement>, A: GroupElement, B:GroupElement) =
        uniformHash(group.order) {
            digest (group.asBytes(statement.baseX))
            digest (group.asBytes(statement.baseY))
            digest (group.asBytes(statement.X))
            digest (group.asBytes(statement.Y))
            digest (group.asBytes(A))
            digest (group.asBytes(B))
        }

}
