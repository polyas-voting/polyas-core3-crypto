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

import de.polyas.core3.crypto.elgamal.CyclicGroup
import de.polyas.core3.crypto.elgamal.MultiCommitmentKey
import de.polyas.core3.crypto.std.SRNG
import java.math.BigInteger

/**
 * An extended Petersen commitment for the zero knowledge proof HLKD17.
 *
 * It also allows the generation of chain commitments and shortcut generation of permutation commitments
 */
class Commitment<GroupElement> private constructor(
    val commitment: List<GroupElement>,
    val randomCoins: List<BigInteger>
) {
    companion object {

        /**
         * Generates a commitment to the given [permutation] w.r.t. the given commitment key [ck].
         *
         * @param group  The underlying cyclic group
         * @param ck  The used commitment key
         * @param permutation  The permutation to commit to
         * @return The computed commitment along with the used random coins
         */
        fun <GroupElement> commitToPermutation(
            group: CyclicGroup<GroupElement>,
            ck: MultiCommitmentKey<GroupElement>,
            permutation: Permutation
        ): Commitment<GroupElement> =
            with(group) {
                val N = permutation.size()
                val randomCoins = List(N) { random(group.order) }
                val commitment = listOfPar(N) { i -> (ck.h pow randomCoins[i]) * ck.hs[permutation[i]] }
                Commitment(commitment, randomCoins)
            }

        /**
         * Computes the chain of commitments `c[0], ... c[N-1]`, where `N` is the length of `u` and
         *
         *      c[i] = h^r[i] * c[i-1]^u[i]
         *
         * with `c[i-1] = cInit`, `h = ck.h`, and freshly generated list of random coins `r` which
         * is returned alongside the commitments.
         *
         * @param ck The used multi-commitment key (only `ck.h` is used)
         * @param cInit The initial element to initiate the chain commitment computations
         * @param u The list of integers to be committed to
         * @return The computed chain commitments and the used random coins
         */
        fun <GroupElement> generateChainCommitment(
            group: CyclicGroup<GroupElement>,
            ck: MultiCommitmentKey<GroupElement>,
            cInit: GroupElement,
            u: List<BigInteger>
        ): Commitment<GroupElement> =
            with(group) {
                val N = u.size
                val r = List(N) { random(group.order) }
                val h = ck.h
                val c: List<GroupElement> =
                    (0 until N).scan(
                        initial = cInit,
                        operation = { previous, i -> (h pow r[i]) * (previous pow u[i]) }
                    )
                    .drop(1) // ignore the initial element
                Commitment(c, r)
            }

        private fun random(upperBound: BigInteger): BigInteger =
            SRNG.nextBigInt(upperBound)
    }
}
