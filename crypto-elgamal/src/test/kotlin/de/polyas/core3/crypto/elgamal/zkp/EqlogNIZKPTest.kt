package de.polyas.core3.crypto.elgamal.zkp

import de.polyas.core3.crypto.elgamal.CyclicGroup
import de.polyas.core3.crypto.elgamal.VerificationResult
import de.polyas.core3.crypto.elgamal.instance.ECElement
import de.polyas.core3.crypto.elgamal.instance.SchnorrGroup
import de.polyas.core3.crypto.elgamal.instance.EllipticCurveInst
import de.polyas.core3.crypto.std.GuardedSRNG
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class EqlogNIZKPTest {
    @Test
    fun testValid() {
        val group: CyclicGroup<BigInteger> = SchnorrGroup.group2048
        testValid(group)
    }

    @Test
    fun testValidEC() {
        val group: CyclicGroup<ECElement> = EllipticCurveInst()
        testValid(group)
    }

    private fun <GroupElem> testValid(group: CyclicGroup<GroupElem>) {
        with (group) {
            val baseX = group.generator
            val exponent = GuardedSRNG.nextBigInt(group.order)
            val baseY: GroupElem = baseX.pow(exponent)
            val x = GuardedSRNG.nextBigInt(group.order)
            val X: GroupElem = baseX.pow(x)
            val Y: GroupElem = baseY.pow(x)
            val statement = EqlogZKP.Statement(baseX, baseY, X, Y)
            val zkp = EqlogNIZKP(group)
            val proof = zkp.createProof(statement, x)
            val proofOk = zkp.verify(statement, proof) is VerificationResult.Correct
            assertTrue(proofOk)
        }
    }

    @Test
    fun testInvalid() {
        val group: CyclicGroup<BigInteger> = SchnorrGroup.group2048
        testInvalid(group)
    }

    @Test
    fun testInvalidEC() {
        val group: CyclicGroup<ECElement> = EllipticCurveInst()
        testInvalid(group)
    }

    private fun <GroupElem> testInvalid(group: CyclicGroup<GroupElem>) {
        with (group) {
            val baseX = group.generator
            val exponent = GuardedSRNG.nextBigInt(group.order)
            val baseY: GroupElem = baseX.pow(exponent)
            val x = GuardedSRNG.nextBigInt(group.order)
            val X: GroupElem = baseX.pow(x)
            val Y: GroupElem = baseY.pow(x)
            val statement = EqlogZKP.Statement(baseX, baseY, X, Y)
            val zkp = EqlogNIZKP(group)
            val statement1 = EqlogZKP.Statement(baseY, baseX, X, Y)
            val proof = zkp.createProof(statement, x)
            val proofOk = zkp.verify(statement1, proof) is VerificationResult.Correct
            assertFalse(proofOk)
        }
    }
}