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
import de.polyas.core3.crypto.elgamal.zkp.DlogNIZKP.Challenger
import de.polyas.core3.crypto.std.uniformHash
import de.polyas.core3.crypto.annotation.Doc
import de.polyas.core3.crypto.std.SRNG
import java.math.BigInteger

/**
 * Non-interactive zero-knowledge proof of the knowledge of discrete logarithms.
 *
 * This class allows one to use non-standard challengers, where a challenger
 * defines the way a challenge is computed. The standard challenger (used if
 * no explicit challenger is provided in the constructor) computes
 * a challenge dependent on the statement (X) and the initial message (A).
 *
 * Non-standard challengers are useful, for example, when the ZKP of discrete
 * logarithms is used as a Schnorr signature (in which case the challenge should
 * also depend on the signed message).
 */
class DlogNIZKP<GroupElem>(
    private val group: CyclicGroup<GroupElem>,
    private val challenger: Challenger<GroupElem> = standardChallenger(group)
) {
    fun interface Challenger<GroupElem> {
        fun challenge(statement: GroupElem, initialMessage: GroupElem): BigInteger
    }

    @Doc("Zero-knowledge proof of the knowledge of discrete logarithms.")
    data class Proof(
        @get:JsonProperty("c") val c: BigInteger,
        @get:JsonProperty("f") val f: BigInteger
    )

    private val q: BigInteger = group.order

    /**
     * Creates a ZKP of knowledge of [secretExponent] such that [X] = generator^x.
     */
    fun createProof(X: GroupElem, secretExponent: BigInteger): Proof {
        val a = SRNG.nextBigInt(q)
        val initialMessage = group.powerOfG(a)
        val challenge = challenger.challenge(X, initialMessage)
        val finalMessage = (a + challenge * secretExponent).mod(q)
        return Proof(challenge, finalMessage)
    }

    /**
     * Verify a proof of a statement X.
     */
    fun verify(X: GroupElem, proof: Proof): VerificationResult =
        with (group) {
            val A = powerOfG(proof.f) / (X pow proof.c)
            val c = challenger.challenge(X, A)

            if (c == proof.c) VerificationResult.Correct
            else VerificationResult.Failed("ZKP of knowledge of discrete logarithms failed (the given challenge is not as expected)")
        }


    companion object {
        fun <GroupElem> standardChallenger(group: CyclicGroup<GroupElem>) = Challenger<GroupElem> { statement, initialMessage ->
            uniformHash(group.order) {
                digest (group.asBytes(group.generator))
                digest (group.asBytes(statement))
                digest (group.asBytes(initialMessage))
            }
        }
    }
}
