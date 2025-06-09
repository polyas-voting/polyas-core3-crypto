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

import java.math.BigInteger
import java.util.stream.IntStream

/**
 * Multi-Commitment scheme. Allows one to commit to n elements at once.
 *
 * @param group A cyclic group over which the computations are carried out
 * @param h A generator of the [group]
 * @param hs Independent generators of the [group].
 *        The number of these generators corresponds to the number of values one can commit at once.
 */
class MultiCommitmentKey<GroupElement>(
    val group: CyclicGroup<GroupElement>,
    val h: GroupElement,
    val hs: List<GroupElement>
) {
    private val n: Int = hs.size

    fun size(): Int = n

    /**
     * Computes a commitment to the given [values] (elements of Zq) with the given
     * random coin [randomness].
     * The number of values must be not greater than n (`hs.size`)
     */
    fun commit(values: List<BigInteger>, randomness: BigInteger): GroupElement = with (group) {
        require(values.size <= n) { "Invalid number of arguments for a multi-commitment" }
        val product = IntStream.range(0, values.size).parallel()
                .mapToObj { i -> hs[i] pow values[i] }
                .reduce(group.identity) { a, b -> a * b }
        (h pow randomness) * product
    }

    /**
     * A special case for only one commited element.
     */
    fun commit(a: BigInteger, r: BigInteger): GroupElement = with (group) {
        (h pow r) * (hs[0] pow a)
    }

    companion object {
        /**
         * Generates the generators of the MultiCommitmentKey using the verifiable method (A.2.3) from fips186-3.
         */
		fun <GroupElement> generateVerifiably(
            group: CyclicGroup<GroupElement>, n: Int, seed: String
        ): MultiCommitmentKey<GroupElement> {
            val generators = group.elementsFromSeed(n + 1, seed)
            val h = generators[0]
            val hs = generators.drop(1)
            return MultiCommitmentKey(group, h, hs)
        }
    }
}
