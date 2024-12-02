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
import de.polyas.core3.crypto.elgamal.Cryptosystem
import de.polyas.core3.crypto.elgamal.CyclicGroup
import de.polyas.core3.crypto.elgamal.VerificationResult
import de.polyas.core3.crypto.elgamal.instance.ECElement
import de.polyas.core3.crypto.elgamal.instance.SchnorrGroup
import de.polyas.core3.crypto.elgamal.instance.EllipticCurveInst
import de.polyas.core3.crypto.std.SRNG
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DecryptionZKPTest {
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
        val cryptosystem = Cryptosystem(group)
        val privateKey = SRNG.nextBigInt(group.order)
        val publicKey = group.powerOfG(privateKey)
        val plaintext = BigInteger.valueOf(117)
        val ciphertext = cryptosystem.encrypt(publicKey, plaintext)

        // decrypt and produce a zkp of valid decryption
        val zkp = DecryptionZKP(group, publicKey)
        val decryptAndProve = zkp.decryptAndProve(ciphertext, privateKey)
        val decrypted = decryptAndProve.plaintext
        val proof = decryptAndProve.proof

        // check that the result of the decryption is ok
        assertEquals(decrypted, plaintext)

        // check the zkp
        val proofOk = zkp.verify(ciphertext, decrypted, proof) is VerificationResult.Correct
        assertTrue(proofOk)
    }

    @Test
    fun testInValid() {
        val group: CyclicGroup<BigInteger> = SchnorrGroup.group2048
        testInvalid(group)
    }

    @Test
    fun testInValidEC() {
        val group: CyclicGroup<ECElement> = EllipticCurveInst()
        testInvalid(group)
    }

    private fun <GroupElem> testInvalid(group: CyclicGroup<GroupElem>) {
        with (group) {
            val privateKey = SRNG.nextBigInt(order)
            val publicKey = powerOfG(privateKey)
            val plaintext = BigInteger.valueOf(117)
            val ciphertext = Cryptosystem(group).encrypt(publicKey, plaintext)

            // decrypt and produce a zkp of valid decryption
            val zkp = DecryptionZKP(group, publicKey)
            val decryptAndProve = zkp.decryptAndProve(ciphertext, privateKey)
            val decrypted = decryptAndProve.plaintext
            val proof = decryptAndProve.proof
            val modifiedX = ciphertext.x * generator
            val modifiedY = ciphertext.y * generator
            val ciphertext1 = Ciphertext(modifiedX, ciphertext.y)
            val ciphertext2 = Ciphertext(ciphertext.x, modifiedY)

            // check the zkp; expect failure
            assertTrue(zkp.verify(ciphertext1, decrypted, proof) is VerificationResult.Failed)
            assertTrue(zkp.verify(ciphertext2, decrypted, proof) is VerificationResult.Failed)
        }
    }
}
