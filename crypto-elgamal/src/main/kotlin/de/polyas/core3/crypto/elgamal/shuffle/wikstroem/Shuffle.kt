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

import de.polyas.core3.crypto.elgamal.Cryptosystem
import de.polyas.core3.crypto.elgamal.CyclicGroup
import de.polyas.core3.crypto.elgamal.MultiCiphertext
import de.polyas.core3.crypto.elgamal.VerificationResult
import de.polyas.core3.crypto.elgamal.VerificationResult.Correct
import de.polyas.core3.crypto.elgamal.VerificationResult.Failed
import de.polyas.core3.crypto.elgamal.MultiCommitmentKey
import de.polyas.core3.crypto.elgamal.shuffle.wikstroem.Commitment.Companion.commitToPermutation
import de.polyas.core3.crypto.elgamal.shuffle.wikstroem.Commitment.Companion.generateChainCommitment
import java.math.BigInteger

/**
 * Re-encryption shuffle for ElGammal ciphertexts with ZKP. It implements the
 * proof of correct shuffle as defined in (HLKD17) (Haenni et al., Pseudo-Code
 * Algorithms for Verifiable Re-Encryption Mix-Nets, 2017).
 *
 * It extends (HLKD12) in that it allows for "parallel shuffling", where l lists
 * of ciphertexts (each of the same length) are shuffled using the same
 * permutation (but independent re-randomization coins). It is useful, when
 * plaintexts are too long to be represented as one group element and (encrypted
 * as one ciphertext) and have to be chopped into l pieces.
 *
 * @param group The underlying cyclic group
 * @param pk The used public (encryption) key
 * @param ck The used multi-commitment key
 */
class Shuffle<GroupElement>(
    private val group: CyclicGroup<GroupElement>,
    private val pk: GroupElement,
    private val ck: MultiCommitmentKey<GroupElement>,
) : CyclicGroup<GroupElement> by group {

    private val cryptoSystem = Cryptosystem(group)

    /**
     * The output of the shuffle. It contains the re-encrypted ciphertexts and the ZK-proof
     */
    data class ShufflePacket<GroupElement>(
        val outputCiphertexts: List<MultiCiphertext<GroupElement>>,
        val proof: ShuffleZKProof<GroupElement>
    )

    /**
     * The output of an unproven shuffle with the witnesses.
     */
    data class UnprovenShufflePacket<GroupElement>(
        val outputCiphertexts: List<MultiCiphertext<GroupElement>>,
        val randomCoins: List<List<BigInteger>>,
        val permutation: Permutation
    )

    /**
     * Shuffles the given [inputCiphertexts] and produces a proof of correct shuffle.
     */
    fun shuffleAndProve(inputCiphertexts: List<MultiCiphertext<GroupElement>>): ShufflePacket<GroupElement> {
        val shufflePacket = genShuffle(inputCiphertexts)
        val shuffleZKProof = genProof(inputCiphertexts, shufflePacket)
        return ShufflePacket(shufflePacket.outputCiphertexts, shuffleZKProof)
    }

    /**
     * Generates the shuffle for a given set of ciphertexts. Follows Algorithm 4.1 (HLDK17)
     *
     * @param inputCiphertexts Ciphertexts to be shuffled. Should contain list of ciphertexts of the same size.
     */
    private fun genShuffle(inputCiphertexts: List<MultiCiphertext<GroupElement>>): UnprovenShufflePacket<GroupElement> {
        val N = inputCiphertexts.size // the number of ciphertexts to mix
        val W = inputCiphertexts[0].size() // the length of the ciphertexts

        val rho = matrix(N, W) { _,_ -> randomFrom2To(group.order) } // random re-encryption coins
        val pi = Permutation.random(N)

        val reRandomizedCiphertexts = listOfPar(N) { i ->
            MultiCiphertext(W, inputCiphertexts[i].auxData) { j ->
                cryptoSystem.reRandomize(inputCiphertexts[i][j], pk, rho[i][j])
            }
        }

        val shuffledCiphertexts = List(N) { i -> reRandomizedCiphertexts[pi.getInv(i)] }

        return UnprovenShufflePacket(shuffledCiphertexts, rho, pi)
    }

    /**
     * Algorithm 4.3 (HLDK17): produces a zero knowledge proof of correctness of shuffle.
     *
     * @param inputCiphertexts The input ciphertexts
     * @param shufflePacket The shuffle packet with no proof
     */
    private fun genProof(
        inputCiphertexts: List<MultiCiphertext<GroupElement>>,
        shufflePacket: UnprovenShufflePacket<GroupElement>
    ) : ShuffleZKProof<GroupElement> {
        val N = inputCiphertexts.size
        val w = inputCiphertexts[0].size() // the length of the ciphertexts
        require(inputCiphertexts.all { it.size() == w }) { "Input ciphertexts of various sizes" }
        val h = ck.h
        val q = group.order
        val hi = ck.hs

        // Line 2 Alg. 4.3
        val com1 = commitToPermutation(group, ck, shufflePacket.permutation)
        val digest = getHashEEC(group, pk, ck, inputCiphertexts, shufflePacket.outputCiphertexts, com1.commitment)
        val u = List(N) { i ->
            digest.continueUniformHash(q) { digest(i + 1) }
        }
        val uPrime = shufflePacket.permutation.applyTo(u)

        // Line 7 Alg. 4.3
        val rBar = com1.randomCoins.sumModulo(q)
        val com2 = generateChainCommitment(group, ck, hi[0], uPrime)
        val rDiamond = computeDiamond(N, q, uPrime, com2.randomCoins)
        val rTilde = sumModulo(N, modulus = q) { i -> com1.randomCoins[i].multiply(u[i]) }
        val rStar = List(w) { j ->
            sumModulo(N, modulus = q) { i -> shufflePacket.randomCoins[i][j] * u[i] }
        }

        // Line 15 Alg. 4.3
        val omega = List(3) { i -> randomFrom2To(q) }
        val omegaFour = List(w) { i -> randomFrom2To(q) }
        val omegaHat = List(N) { i -> randomFrom2To(q) }
        val omegaPrime = List(N) { i -> randomFrom2To(q) }
        val t1 = h pow omega[0]
        val t2 = h pow omega[1]
        val t3 = (h pow omega[2]) * productPar(N) { i -> hi[i] pow omegaPrime[i] }
        val t4_1 = List(w) { j ->
            (pk pow -omegaFour[j]) * productPar(N) { i -> shufflePacket.outputCiphertexts[i][j].y pow omegaPrime[i] }
        }
        val t4_2 = List(w) { j ->
            group.powerOfG(-omegaFour[j]) * (sequencePar(N) { i -> shufflePacket.outputCiphertexts[i][j].x pow omegaPrime[i] }.product())
        }
        val tHat = listOfPar(N) { i ->
            val ciHat = if (i == 0) hi[0] else com2.commitment[i - 1]
            (h pow omegaHat[i]) * (ciHat pow omegaPrime[i])
        }
        val t = ZKPt(t1, t2, t3, t4_1, t4_2, tHat)
        val c = getFinalHash(digest, com2.commitment, t, group)

        // Line 28 Alg. 4.3
        val s1 = (omega[0] + c*rBar).mod(q)
        val s2 = (omega[1] + c*rDiamond).mod(q)
        val s3 = (omega[2] + c*rTilde).mod(q)
        val s4 = List(w) { j -> (omegaFour[j] + c * rStar[j]).mod(q) }
        val sHat = List(N) { i -> (omegaHat[i] + c * com2.randomCoins[i]).mod(q) }
        val sPrime = List(N) { i -> (omegaPrime[i] + c * uPrime[i]).mod(q) }
        return ShuffleZKProof(t, ZKPs(s1, s2, s3, s4, sHat, sPrime), com1.commitment, com2.commitment)
    }

    private fun computeDiamond(n: Int, q: BigInteger, B: List<BigInteger>, A: List<BigInteger>): BigInteger {
        var s = BigInteger.ZERO
        var prod = BigInteger.ONE
        for (i in n - 1 downTo 0) {
            val x = A[i] * prod
            prod = (prod * B[i]).mod(q)
            s = (s + x).mod(q)
        }
        return s
    }

    /**
     * Checks the [proof] of correct shuffle which guarantees that the output * ciphertexts [oc]
     * have been obtained by re-encryption and re-ordering from the input ciphertexts [ic].
     *
     * @param proof The ZKP of correct shuffle
     * @param ic The input ciphertexts
     * @param oc The output ciphertexts
     *
     * @return Success if the proof is correct
     */
    fun checkProof(
        proof: ShuffleZKProof<GroupElement>,
        ic: List<MultiCiphertext<GroupElement>>,
        oc: List<MultiCiphertext<GroupElement>>
    ): VerificationResult {
        // Initial checks and definitions
        val N = ic.size
        VerificationResult
            .expect (ic.size == oc.size) { "The number of input and output ciphertexts is not the same: ${ic.size} ${oc.size}" }
            .andExpect ( N > 0) { "A mixing packet cannot be empty" }
            .andExpect (proof.c.size == N) { "Wrong size of proof.c" }
            .andExpect (proof.cHat.size == N) { "Wrong size of proof.cHat"}
            .onFailure { return it }
        val w = ic[0].size()
        VerificationResult
            .expect (ic.all { it.size() == w }) { "Input ciphertexts of various sizes" }
            .andExpect (oc.all { it.size() == w }) { "Output ciphertexts of various sizes" }
            .andExpect (proof.t.t4y.size == w) { "Wrong size of proof.t.t4y" }
            .andExpect (proof.t.t4x.size == w) { "Wrong size of proof.t.t4x" }
            .andExpect (proof.t.tHat.size == N) { "Wrong size of proof.t.tHat" }
            .andExpect (proof.s.s4.size == w) { "Wrong size of proof.s4" }
            .andExpect (proof.s.sHat.size == N) { "Wrong size of proof.s.sHat"}
            .andExpect (proof.s.sPrime.size == N) { "Wrong size of proof.sPrime" }
            .onFailure { return it }

        val q = group.order
        val hi = ck.hs
        val h = ck.h

        // Compute the vector u
        val digest = getHashEEC(group, pk, ck, ic, oc, proof.c)
        val u = List(N) { i ->
            digest.continueUniformHash(q) { digest(i + 1) }
        }

        // Derive the final challenge c
        val c = getFinalHash(digest, proof.cHat, proof.t, group)

        // Compute the values t1, t2, t4 (the "x" and the "y" parts), tHat to be compared with the values in the proof
        val cBar = product(N){ i -> proof.c[i] } * inverse(product(N){ i -> hi[i] })
        val t1 = (cBar pow -c) * (h pow proof.s.s1)

        val cHat = inverse(hi[0] pow u.prodModulo(q)) * proof.cHat[N - 1]
        val t2 = (cHat pow -c) * (h pow proof.s.s2)

        val cTilde = productPar(N) { i -> proof.c[i] pow u[i] }
        val t3 = (cTilde pow -c) * (h pow proof.s.s3) * productPar(N) { i -> hi[i] pow proof.s.sPrime[i] }

        val aPrime = List(w) { j ->
            productPar(N) { i -> ic[i][j].y pow u[i] }
        }
        val t4y = List(w) { j ->
            (aPrime[j] pow -c) * (pk pow -proof.s.s4[j]) * productPar(N) { i -> oc[i][j].y pow proof.s.sPrime[i] }
        }

        val bPrime = List(w) { j ->
            productPar(N) { i -> ic[i][j].x pow u[i] }
        }
        val t4x = List(w) { j ->
            (bPrime[j] pow -c) * powerOfG(-proof.s.s4[j]) * productPar(N) { i -> oc[i][j].x pow proof.s.sPrime[i] }
        }

        val tHatPrime = listOfPar(N) { i ->
            val cHatMinus1 = if (i == 0) hi[0] else proof.cHat[i - 1]
            (proof.cHat[i] pow -c) * h.pow(proof.s.sHat[i]) * cHatMinus1.pow(proof.s.sPrime[i])
        }
        val tHatCorrect = (0 until N).all { i -> tHatPrime[i] == proof.t.tHat[i] }

        return when {
            t1 != proof.t.t1 -> Failed("verification of part 1 failed")
            t2 != proof.t.t2 -> Failed("verification of part 2 failed")
            t3 != proof.t.t3 -> Failed("verification of part 3 failed")
            t4y != proof.t.t4y -> Failed("verification of part 4.1 failed")
            t4x != proof.t.t4x -> Failed("verification of part 4.2 failed")
            !tHatCorrect -> Failed("verification of part 5 failed")

            else -> Correct
        }
    }
}
