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

/**
 * Pedersen's commitments over the given cyclic group.
 *
 * This commitment scheme is _perfectly hiding_ and _computationally binding_.
 *
 * The commitment key is determined using function [CyclicGroup.elementsFromSeed]
 * with the seed value "pedersen-commitment-key".
 */
class Pedersen<GroupElement>(val group: CyclicGroup<GroupElement>) {

    val commitmentKey: GroupElement = group.generateCommitmentKey()

    /**
     * Computes a commitment to the given [value], using the explicitly provided [randomCoin].
     */
    fun commit(value: BigInteger, randomCoin: BigInteger) : GroupElement = with (group) {
        (generator pow value) * (commitmentKey pow randomCoin)
    }
}

private fun <GroupElement> CyclicGroup<GroupElement>.generateCommitmentKey() : GroupElement =
    elementsFromSeed(1, "pedersen-commitment-key")[0]
