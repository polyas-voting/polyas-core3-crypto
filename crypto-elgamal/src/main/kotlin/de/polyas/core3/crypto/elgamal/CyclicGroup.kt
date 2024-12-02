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
 * Abstract cyclic group.
 *
 * @param GroupElement  The element type, that is the type used to represent group elements.
 */
interface CyclicGroup<GroupElement> {

    /**
     * The order of the group
     */
    val order: BigInteger

    /**
     * The neutral element of the group
     */
    val identity: GroupElement

    /**
     * A generator of the group.
     */
    val generator: GroupElement

    /**
     * The upper bound of the range of valid messages (integers that can be encoded as a group element).
     *
     * For simple groups this value will be the same as 'order()'. However, for efficiency reasons,
     * some other groups (EC based groups) encode smaller range of integers.
     */
    fun messageUpperBound(): BigInteger

    /**
     * Generates n pseudo-random element in the group from the given seed.
     * Most commonly used to get independent generators.
     */
    fun elementsFromSeed(n: Int, seed: String): List<GroupElement>

    /**
     * Multiplies two group elements.
     */
    operator fun GroupElement.times(other: GroupElement): GroupElement

    /**
     * Divides two group elements.
     */
    operator fun GroupElement.div(other: GroupElement) : GroupElement = this * (inverse(other))

    /**
     * Raises this group element (receiver) to the power of [exponent], where the exponent is
     * an integer (typically in the range [0, order).
     */
    infix fun GroupElement.pow(exponent: BigInteger): GroupElement

    /**
     * Returns the inverse of the group element [a].
     */
    fun inverse(a: GroupElement): GroupElement

    /**
     * Encodes an integer in the range [0, messageUpperBound) as a group element.
     * Method [decode] is the inverse of this operation.
     */
    fun encode(a: BigInteger): GroupElement

    /**
     * Decodes a group element back to the set [0, messageUpperBound).
     * This is the inverse of the [encode] operation.
     */
    fun decode(a: GroupElement): BigInteger

    /**
     * Returns the canonical byte representation of the given group element.
     */
    fun asBytes(groupElement: GroupElement): ByteArray

    /**
     * Returns the canonical string representation of the given group element.
     */
    fun asCanonicalString(groupElement: GroupElement): String

    /**
     * Creates a group element from its canonical byte representation or returns `null`
     * if the given byte array is not a valid representation of a group element.
     */
    fun fromBytes(bytes: ByteArray): GroupElement?

    /**
     * Check if the given value is a valid element of the group.
     */
    fun validGroupElement(a: GroupElement): Boolean

    // Default implementation of some derived operations:

    /**
     * Returns the generator to the power of exp.
     */
    fun powerOfG(exp: BigInteger): GroupElement =
        generator pow exp

    /**
     * Returns all the elements of this sequence multiplied together
     */
    fun Sequence<GroupElement>.product(): GroupElement =
        this.fold(identity) { a: GroupElement, b: GroupElement -> a*b }

    /**
     * Returns all the elements of this sequence multiplied together
     */
    fun Iterable<GroupElement>.product(): GroupElement =
        this.fold(identity) { a: GroupElement, b: GroupElement -> a*b }

    /**
     * Returns the product of all values produced by selector function applied to
     * each element in the sequence.
     */
    fun <A> Iterable<A>.productOf(selector: (A) -> GroupElement): GroupElement =
        this.asSequence().map(selector).fold(identity) { a: GroupElement, b: GroupElement -> a*b }

    /**
     * Checks if the given integer is a valid plaintext, i.e. it is in the range [0, messageUpperBound)
     */
    fun validPlaintext(a: BigInteger): Boolean {
        val b = messageUpperBound()
        return a >= BigInteger.ZERO && a < b
    }
}
