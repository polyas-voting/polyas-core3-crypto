/*
 * Copyright 2025 Polyas GmbH
 *
 * Licensed under GNU Affero General Public License v3.0; you may not use
 * this file except in compliance with the License. You may obtain a copy of
 * the License at https://www.gnu.org/licenses/agpl-3.0.en.html.
 * This software is distributed WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
 * either express or implied.
 */
package de.polyas.core3.crypto.elgamal

import de.polyas.core3.crypto.elgamal.instance.ECElement
import de.polyas.core3.crypto.elgamal.instance.EllipticCurveInst
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PedersenTest {
    private val group = EllipticCurveInst()

    @Test
    fun `the commitment key has the expected value`() {
        val expectedKeyHex = "0373744f99d31509eb5f8caaabc0cc3fab70e571a5db4d762020723b9cd6ada260"
        val expectedCommitmentKey = ECElement.fromHexString(expectedKeyHex)
        assertEquals(expectedCommitmentKey, Pedersen(group).commitmentKey)
        val derived = group.elementsFromSeed(1, "pedersen-commitment-key")[0]
        assertEquals(expectedCommitmentKey, derived)
    }

    @Test
    fun `commitments are as expected (a fixture)`() {
        val value = BigInteger("42")
        val randomCoin = BigInteger("1897394776788888888854555455455455455455455455455455765")
        val c = Pedersen(group).commit(value, randomCoin)
        val expected = "021d51f3a8dd18477bafcb5e149314d6e03669bbfc65bf8cb975f46e2527be7901"
        assertEquals(expected, c.asHexString())
    }

    @Test
    fun `commitments are different for different values`() {
        val randomCoin = BigInteger("18973947767888888888878987987666")
        val c1 = Pedersen(group).commit(BigInteger.valueOf(10), randomCoin)
        val c2 = Pedersen(group).commit(BigInteger.valueOf(11), randomCoin)
        assertTrue(c1 != c2)
    }

    @Test
    fun `commitments are different for different random coins`() {
        val randomCoin = BigInteger("18973947767888888888878987987666")
        val c1 = Pedersen(group).commit(BigInteger.valueOf(10), randomCoin)
        val c2 = Pedersen(group).commit(BigInteger.valueOf(10), randomCoin + BigInteger.ONE)
        assertTrue(c1 != c2)
    }

    @Test
    fun `commitments are equal for equal randomness mod q`() {
        val value = BigInteger("42")
        val randomCoin =
            BigInteger("18973947767888888888888888888888888889999999999999999998722426787656754678765476567854555455455455455455455455455455765")
        val randomCoinClipped = randomCoin % group.order
        val c1 = Pedersen(group).commit(value, randomCoin)
        val c2 = Pedersen(group).commit(value, randomCoinClipped)
        assertEquals(c1, c2)
    }

    @Test
    fun `commitment for the second device protocol matched the fixture`() {
        val group = group

        val commitmentKey = ECElement.fromHexString("0373744f99d31509eb5f8caaabc0cc3fab70e571a5db4d762020723b9cd6ada260")
        val challenge = BigInteger("108039209026641834721998202775536164454916176078442584841940316235417705823230")
        val challengeRandomCoin = BigInteger("44267717001895006656767798790813376597351395807170189462353830054915294464906")
        val challengeCommitment = ECElement.fromHexString("030e1a9be2459151057e9d731b524ca435f1c05bc0a95d3d82b30512d306172b17")

        val computed = with (group) {
            (generator pow challenge) * (commitmentKey pow challengeRandomCoin)
        }

        assertEquals(challengeCommitment, computed)
    }
}
