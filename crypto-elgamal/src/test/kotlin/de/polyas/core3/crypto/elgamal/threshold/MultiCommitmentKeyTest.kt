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

import de.polyas.core3.crypto.elgamal.MultiCommitmentKey
import de.polyas.core3.crypto.elgamal.instance.SchnorrGroup
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals

class MultiCommitmentKeyTest {

    @Test
    fun testCommit() {
        val n = 10
        val group = SchnorrGroup.group512
        val ck = MultiCommitmentKey.generateVerifiably(group, n, "seed")
        val v1 = BigInteger.valueOf(10)
        val v2 = BigInteger.valueOf(43)
        val randomness = BigInteger.valueOf(88897375)

        val commitment = ck.commit(listOf(v1, v2), randomness)

        val expected = with (group) {
            (ck.h pow randomness) * (ck.hs[0] pow v1) * (ck.hs[1] pow v2)
        }

        assertEquals(expected, commitment)
    }

    @Test
    fun testCommitOneValue() {
        val n = 2
        val group = SchnorrGroup.group512
        val ck = MultiCommitmentKey.generateVerifiably(group, n, "seed")
        val v1 = BigInteger.valueOf(10)
        val randomness = BigInteger.valueOf(88897375)

        val commitment = ck.commit(v1, randomness)
        val expected = ck.commit(listOf(v1), randomness)

        assertEquals(expected, commitment)
    }

    @Test
    fun testGenerate() {
        val n = 100
        val group = SchnorrGroup.group512
        val commitmentKey = MultiCommitmentKey.generateVerifiably(group, n, "seed")
        assertEquals(n, commitmentKey.size())
        assertEquals(n, commitmentKey.hs.size)
        commitmentKey.hs.forEach {
            group.validGroupElement(it)
        }
    }
}
