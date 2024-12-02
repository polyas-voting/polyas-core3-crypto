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
