/*
 * Copyright 2025 Polyas GmbH
 *
 * Licensed under GNU Affero General Public License v3.0; you may not use
 * this file except in compliance with the License. You may obtain a copy of
 * the License at https://www.gnu.org/licenses/agpl-3.0.en.html.
 * This software is distributed WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
 * either express or implied.
 */
package de.polyas.core3.crypto.elgamal.threshold

import de.polyas.core3.crypto.elgamal.Cryptosystem
import de.polyas.core3.crypto.elgamal.CyclicGroup
import de.polyas.core3.crypto.elgamal.instance.ECElement
import de.polyas.core3.crypto.elgamal.instance.SchnorrGroup
import de.polyas.core3.crypto.elgamal.instance.EllipticCurveInst
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals

class ThresholdDecryptionTest {
    @Test
    fun testBasicUsageStandardGroup() {
        val group: CyclicGroup<BigInteger> = SchnorrGroup.group512
        testBasicUsage(group)
    }

    @Test
    fun testBasicUsageEC() {
        val group: CyclicGroup<ECElement> = EllipticCurveInst()
        testBasicUsage(group)
    }

    private fun <GroupElem> testBasicUsage(group: CyclicGroup<GroupElem>) {
        val cryptosystem = Cryptosystem(group)

        // Parameters
        val t = 3
        val n = 5
        val config = ThresholdConfig(t, n)
        val th = ThresholdDecryption(config, group)

        // Key initialization
        val keyGenTellers = (1 .. n).map { i -> th.newKeyGen(tellerIndex = i) }

        // Commitments to the polynomial
        val publicKeyContributions = keyGenTellers.map { teller -> teller.blindedCoefficients[0] }

        // Finalize to produce private key shares
        val privateKeyShares = keyGenTellers.map { teller -> finalize(teller, keyGenTellers) }

        // Compute the public key
        val publicKey = th.publicKeyFromContributions(publicKeyContributions)

        // Encryption (just ordinary ElGamal encryption)
        val plaintext = BigInteger("1234567890")
        val encrypted = cryptosystem.encrypt(publicKey, plaintext)

        // Decryption
        val decryptionShares = privateKeyShares.map { keyShare ->
            th.decryptionShare(keyShare, encrypted)
        }
        val selectedShares = decryptionShares.filter { share -> share.nr <= t }
        val dec = th.finalizeDecryption(encrypted, selectedShares)
        assertEquals(plaintext, dec)
    }

    @Test
    fun testZKPStandardGroup() {
        val group: CyclicGroup<BigInteger> = SchnorrGroup.group512
        testZKP(group)
    }

    @Test
    fun testZKPEC() {
        val group: CyclicGroup<ECElement> = EllipticCurveInst()
        testZKP(group)
    }

    private fun <GroupElem> testZKP(group: CyclicGroup<GroupElem>) {
        val cryptosystem = Cryptosystem(group)

        val t = 2
        val n = 3
        val tsconfig = ThresholdConfig(t, n)
        val th = ThresholdDecryption(tsconfig, group)

        val keyGenTellers = (1 .. n).map { i -> th.newKeyGen(i) }
        val publicKeyContributions = keyGenTellers.map { teller -> teller.blindedCoefficients[0] }
        val privateKeyShares = keyGenTellers.map { teller -> finalize(teller, keyGenTellers) }
        val blindedCoefficients: List<List<GroupElem>> = keyGenTellers.map { teller -> teller.blindedCoefficients }
        val pksMap: Map<Int, GroupElem> = (0 until n)
            .associate { ind -> ind + 1 to th.publicKeyShareFromBlindedCoefficients(blindedCoefficients, ind) }
        val publicKey = th.publicKeyFromContributions(publicKeyContributions)
        val plaintext = BigInteger("1234567890")
        val encrypted = cryptosystem.encrypt(publicKey, plaintext)
        val decryptionShares: List<DecryptionShare<GroupElem>> = privateKeyShares.map { ks ->
            th.decryptionShare(ks, encrypted)
        }
        val selectedShares: List<DecryptionShare<GroupElem>> = decryptionShares.filter { (nr) -> nr <= t }
        selectedShares.forEach { s: DecryptionShare<GroupElem> ->
            th.verifyDecryptionShareZKP(s, encrypted, pksMap[s.nr]!!)
        }
        val dec = th.finalizeDecryption(encrypted, selectedShares)
        assertEquals(plaintext, dec)
    }

    @Test
    fun testPublicKeyOfTeller1of1() {
        val group: CyclicGroup<ECElement> = EllipticCurveInst()
        testPublicKeyOfTeller(group, 1, 1)
    }

    @Test
    fun testPublicKeyOfTeller2of3() {
        val group: CyclicGroup<ECElement> = EllipticCurveInst()
        testPublicKeyOfTeller(group, 2, 3)
    }

    @Test
    fun testPublicKeyOfTeller3of3() {
        val group: CyclicGroup<ECElement> = EllipticCurveInst()
        testPublicKeyOfTeller(group, 3, 3)
    }

    private fun <GroupElem> testPublicKeyOfTeller(group: CyclicGroup<GroupElem>, t: Int, n: Int) {
        val tsconfig = ThresholdConfig(t, n)
        val th = ThresholdDecryption(tsconfig, group)

        // Key initialization
        val keyGenTellers = (1..n).map { i: Int -> th.newKeyGen(i) }
        val blindedCoefficients = keyGenTellers.map { it.blindedCoefficients }
        val privateKeyShares = keyGenTellers.map { teller -> finalize(teller, keyGenTellers) }

        for (i in 0 until n) {
            assertEquals(
                th.publicKeyShareFromBlindedCoefficients(blindedCoefficients, i),
                privateKeyShares[i].commitment
            )
        }
    }

    private fun <GroupElem> finalize(
        teller: ThresholdDecryption<GroupElem>.Teller,
        allTellers: List<ThresholdDecryption<GroupElem>.Teller>
    ): PrivateKeyShare<GroupElem> {
        val sharedData = allTellers.asSequence()
            .filter { other -> other.nr != teller.nr }
            .map { other -> other.dataSharedWith(teller.nr) }
            .toList()
        return teller.finalize(sharedData).getOrElse { error(it) }
    }
}
