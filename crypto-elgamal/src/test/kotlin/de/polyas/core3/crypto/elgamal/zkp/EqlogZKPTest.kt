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

import de.polyas.core3.crypto.elgamal.CyclicGroup
import de.polyas.core3.crypto.elgamal.VerificationResult
import de.polyas.core3.crypto.elgamal.instance.SchnorrGroup
import de.polyas.core3.crypto.elgamal.instance.EllipticCurveInst
import de.polyas.core3.crypto.elgamal.zkp.EqlogZKP.InteractiveProver
import de.polyas.core3.crypto.std.SRNG
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertTrue

class EqlogZKPTest {
    @Test
    fun testInteractive() {
        testInteractive(SchnorrGroup.group2048)
    }

    @Test
    fun testInteractiveEC() {
        testInteractive(EllipticCurveInst())
    }

    private fun <GroupElem> testInteractive(group: CyclicGroup<GroupElem>) {
        with(group) {
            val baseX = group.generator
            val exponent = SRNG.nextBigInt(group.order)
            val baseY: GroupElem = baseX.pow(exponent)
            val x = SRNG.nextBigInt(group.order)
            val X: GroupElem = baseX.pow(x)
            val Y: GroupElem = baseY.pow(x)
            val statement = EqlogZKP.Statement(baseX, baseY, X, Y)
            val prover = InteractiveProver(group, statement, x)
            val verifier = EqlogZKP.Verifier(group, statement)
            val initialMessage = prover.initialMessage
            val challenge = verifier.challenge()
            val finalMessge = prover.finalMessage(challenge)
            assertTrue(verifier.verify(initialMessage, challenge, finalMessge) is VerificationResult.Correct)
        }
    }

    @Test
    fun testInvalid() {
        testInvalid(SchnorrGroup.group2048)
    }

    @Test
    fun testInvalidEC() {
        testInvalid(EllipticCurveInst())
    }

    private fun <GroupElem> testInvalid(group: CyclicGroup<GroupElem>) {
        with (group) {
            val baseX = group.generator
            val exponent = SRNG.nextBigInt(group.order)
            val baseY: GroupElem = baseX.pow(exponent)
            val x = SRNG.nextBigInt(group.order)
            val X: GroupElem = baseX.pow(x)
            val Y: GroupElem = baseY.pow(x)
            val statement = EqlogZKP.Statement(baseX, baseY, X, Y)
            val x1 = x.add(BigInteger.ONE) // we take a different secret
            val prover = InteractiveProver(group, statement, x1)
            val verifier = EqlogZKP.Verifier(group, statement)
            val initialMessage = prover.initialMessage
            val challenge = verifier.challenge()
            val finalMessge = prover.finalMessage(challenge)
            assertTrue(verifier.verify(initialMessage, challenge, finalMessge) is VerificationResult.Failed)
        }
    }
}
