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
import de.polyas.core3.crypto.std.SRNG
import de.polyas.core3.crypto.std.uniformHash
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertTrue

class DlogZKPTest {
    @Test
    fun testBasic() {
        testBasic(SchnorrGroup.group2048)
    }

    @Test
    fun testBasicEC() {
        testBasic(EllipticCurveInst())
    }

    private fun <GroupElem> testBasic(group: CyclicGroup<GroupElem>) {
        // take a secret x and compute a statement X
        val x = SRNG.nextBigInt(group.order)
        val X = group.powerOfG(x)

        // create a ZKP
        val dlogZKP = DlogNIZKP(group)
        val proof = dlogZKP.createProof(X, x)

        // verify the ZKP
        assertTrue(dlogZKP.verify(X, proof) is VerificationResult.Correct)

        // it shouldn't work always:
        val X1 = with(group) { X * X }
        assertTrue(dlogZKP.verify(X1, proof) is VerificationResult.Failed)
    }

    @Test
    fun testNotStandardChallenger() {
        testNotStandardChallenger(SchnorrGroup.group2048)
    }

    @Test
    fun testNotStandardChallengerEC() {
        testNotStandardChallenger(EllipticCurveInst())
    }

    private fun <GroupElem> testNotStandardChallenger(group: CyclicGroup<GroupElem>) {
        val dlogZKP = DlogNIZKP(
            group
        )  // provide some non-standard challenger
        { X: GroupElem, A: GroupElem ->
            uniformHash(group.order) {
                digest(BigInteger.ONE)
                digest(group.asBytes(X))
            }
        }
        val x = SRNG.nextBigIntInRange(BigInteger.ZERO, group.order)
        val X = group.powerOfG(x)
        val proof = dlogZKP.createProof(X, x)
        assertTrue(dlogZKP.verify(X, proof) is VerificationResult.Correct)
    }
}
