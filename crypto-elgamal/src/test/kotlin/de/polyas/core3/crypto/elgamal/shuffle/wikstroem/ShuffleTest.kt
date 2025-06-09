/*
 * Copyright 2025 Polyas GmbH
 *
 * Licensed under GNU Affero General Public License v3.0; you may not use
 * this file except in compliance with the License. You may obtain a copy of
 * the License at https://www.gnu.org/licenses/agpl-3.0.en.html.
 * This software is distributed WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
 * either express or implied.
 */
package de.polyas.core3.crypto.elgamal.shuffle.wikstroem

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import de.polyas.core3.crypto.elgamal.Cryptosystem
import de.polyas.core3.crypto.elgamal.MultiCiphertext
import de.polyas.core3.crypto.elgamal.VerificationResult
import de.polyas.core3.crypto.elgamal.instance.ECElement
import de.polyas.core3.crypto.elgamal.instance.SchnorrGroup
import de.polyas.core3.crypto.elgamal.instance.SchnorrGroup.Companion.group
import de.polyas.core3.crypto.elgamal.instance.EllipticCurveInst
import de.polyas.core3.crypto.elgamal.MultiCommitmentKey.Companion.generateVerifiably
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class ShuffleTest {
    @Test
    fun `summing modulo`() {
        val n = 10
        val mod = BigInteger.valueOf(100)
        val s = Sequence(n) { i -> BigInteger.valueOf(i.toLong()) }.sumModulo(mod)
        val expected = (0 until n)
            .map { BigInteger.valueOf(it.toLong()) }
            .fold(BigInteger.ZERO, BigInteger::add)
            .mod(mod)
        assertEquals(expected, s)
    }


    @Test
    fun `product modulo`() {
        val n = 10
        val mod = BigInteger.valueOf(6987)
        val s = Sequence(n) { i -> BigInteger.valueOf((i + 1).toLong()) }.prodModulo(mod)
        val expected = (0 until n)
            .map { BigInteger.valueOf((it + 1).toLong()) }
            .fold(BigInteger.ONE, BigInteger::times)
            .mod(mod)
        assertEquals(expected, s)
    }

    @Test
    fun sequence() {
        val values = listOf(1,7,4,2)
        val seq = Sequence(values.size) { i -> values[i] }
        val seqList = seq.toList()
        assertEquals(values, seqList)
    }

    @Test
    fun permutation() {
        val n = 40
        val permutation = Permutation.random(n)
        val values = Sequence(permutation.size()) { i -> permutation[i] }
            .toSet()
        assertEquals(n, values.size)
        values.forEach {
            assertTrue(it in 0 until n)
        }
    }

    @Test
    fun `reverse permutation`() {
        val n = 40
        val permutation = Permutation.random(n)
        for (i in 0 until n) {
            val j = permutation[i]
            assertEquals(i, permutation.getInv(j))
        }
    }

    @Test
    fun testProofCreationAndVerificationEC() {
        val n = 20 // Number of ciphertexts
        val group = EllipticCurveInst()
        val privateKey = group.order.divide(BigInteger("2"))
        val publicKey = group.powerOfG(privateKey)
        val ck = generateVerifiably(group, n, "Polyas")
        val cryptoSystem = Cryptosystem(group)
        val c = List(n) { randomCiphertext(cryptoSystem, publicKey, group.messageUpperBound(), 3) }
        val shuffle = Shuffle(group, publicKey, ck)
        val packet = shuffle.shuffleAndProve(c)

        val mapper = jacksonObjectMapper()
        val packetJson = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(packet)
        val deserializedPacket : Shuffle.ShufflePacket<ECElement> = mapper.readValue(packetJson)

        assertTrue(shuffle.checkProof(deserializedPacket.proof, c, deserializedPacket.outputCiphertexts) is VerificationResult.Correct)
    }

    @Test
    fun testProofCreationAndVerificationFail() {
        val n = 5 // Number of ciphertexts
        val group = group(SchnorrGroup.Bits.BITS_2048)
        val privateKey = group.order.divide(BigInteger("2"))
        val publicKey = group.powerOfG(privateKey)
        val ck = generateVerifiably(group, n, "Polyas")
        val cryptoSystem = Cryptosystem(group)
        val c = List(n) { randomCiphertext(cryptoSystem, publicKey, group.order, 3) }
        val shuffle = Shuffle(group, publicKey, ck)
        val packet = shuffle.shuffleAndProve(c)
        val packet1 = packet.copy(outputCiphertexts = packet.outputCiphertexts + randomCiphertext(cryptoSystem, publicKey, group.order, 3))
        assertIs<VerificationResult.Failed>(shuffle.checkProof(packet1.proof, c, packet1.outputCiphertexts))
    }
}

/**
 * Generates a new random ciphertext of length [len].
 */
private fun <GroupElement> randomCiphertext(
    cryptoSystem: Cryptosystem<GroupElement>, pk: GroupElement, Q: BigInteger, len: Int
): MultiCiphertext<GroupElement> =
    MultiCiphertext(len) { cryptoSystem.encrypt(pk, randomFrom2To(Q)) }
