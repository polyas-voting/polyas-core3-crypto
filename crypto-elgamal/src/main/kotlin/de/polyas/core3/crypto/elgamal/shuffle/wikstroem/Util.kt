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
import de.polyas.core3.crypto.elgamal.MultiCiphertext
import de.polyas.core3.crypto.elgamal.MultiCommitmentKey
import de.polyas.core3.crypto.std.SRNG
import de.polyas.core3.crypto.std.PartialDigest
import de.polyas.core3.crypto.std.initialDigestSha512
import java.math.BigInteger
import java.util.stream.Collectors
import java.util.stream.IntStream
import kotlin.streams.asSequence

/**
* Returns a random biginteger in range [2, upperbound).
*/
internal fun randomFrom2To(upperBound: BigInteger): BigInteger =
    SRNG.nextBigIntInRange(BigInteger.TWO, upperBound)

/**
 * Sums this sequence of big integers modulo the given [modulus].
 */
internal fun Iterable<BigInteger>.sumModulo(modulus: BigInteger): BigInteger =
    this.asSequence().sumModulo(modulus)

/**
 * Sums this sequence of big integers modulo the given [modulus].
 */
internal fun Sequence<BigInteger>.sumModulo(modulus: BigInteger): BigInteger =
     this.fold(BigInteger.ZERO){ a: BigInteger, b: BigInteger -> a.add(b).mod(modulus) }

/**
 * Sums n elements provided by the [provider] modulo [modulus]
 */
internal fun sumModulo(n:Int, modulus: BigInteger, provider: (Int) -> BigInteger): BigInteger =
    Sequence(n, provider).sumModulo(modulus)

/**
 * Creates a sequence of length [len] using the given initialization function [init] to determine
 * the value of the elements.
 */
internal fun <A> Sequence(len: Int, init: (Int) -> A) =
    (0 until len).asSequence().map(init)

/**
 * Returns sequence of init(0), ..., init(N-1), performing the computations in parallel
 */
internal fun <A> sequencePar(N: Int, init: (Int) -> A): Sequence<A> =
    IntStream.range(0, N).parallel().mapToObj(init).asSequence()

/**
 * Multiplies this sequence of big integers modulo the given modulus.
 */
fun Sequence<BigInteger>.prodModulo(modulus: BigInteger): BigInteger =
    this.fold(BigInteger.ONE) { a: BigInteger, b: BigInteger -> a.multiply(b).mod(modulus) }

/**
 * Multiplies this sequence of big integers modulo the given modulus.
 */
fun Iterable<BigInteger>.prodModulo(modulus: BigInteger): BigInteger = this.asSequence().prodModulo(modulus)

/**
 * Creates a matrix (list of lists) of size [n]x[m], using the give [init] function
 * to determine the value of the elements
 */
internal fun <T> matrix(n: Int, m: Int, init: (Int, Int) -> T ): List<List<T>> =
    List(n) { i ->
        List(m) { j -> init(i,j) }
    }

/**
 * Computes the list of values in parallel.
 */
internal fun <T> listOfPar(len: Int, init: (Int) -> T): List<T> =
    IntStream.range(0, len).parallel().mapToObj(init).collect(Collectors.toList())

/**
 * Computes the product of the group elements.
 */
internal fun <G> CyclicGroup<G>.product(len: Int, element: (Int) -> G) : G =
    Sequence(len, element).product()

/**
 * Computes the product of the group elements, carrying out the computations in parallel.
 */
internal fun <G> CyclicGroup<G>.productPar(len: Int, element: (Int) -> G) : G =
    sequencePar(len, element).product()

/**
 * Utility to hash variables in the (HLKD17) zero knowledge proof
 */
internal fun <GroupElement> getHashEEC(
    group: CyclicGroup<GroupElement>,
    pk: GroupElement,
    ck: MultiCommitmentKey<GroupElement>,
    inputCiphertexts: List<MultiCiphertext<GroupElement>>,
    outputCiphertexts: List<MultiCiphertext<GroupElement>>,
    c: List<GroupElement>
): PartialDigest =
    initialDigestSha512 {
        val N = inputCiphertexts.size
        val W = inputCiphertexts[0].size()
        digest(group.asBytes(group.generator))
        digest(group.asBytes(pk))
        digest(group.asBytes(ck.h))
        for (i in 0 until N) {
            digest(group.asBytes(ck.hs[i]))
        }
        for (i in 0 until N) {
            for (j in 0 until W) {
                digest(group.asBytes(inputCiphertexts[i][j].x))
                digest(group.asBytes(inputCiphertexts[i][j].y))
            }
        }
        for (i in 0 until N) {
            for (j in 0 until W) {
                digest(group.asBytes(outputCiphertexts[i][j].x))
                digest(group.asBytes(outputCiphertexts[i][j].y))
            }
        }
        for (i in 0 until N) {
            digest(group.asBytes(c[i]))
        }
    }

/**
 * Utility to hash variables in the (HLKD17) zero knowledge proof
 */
internal fun <GroupElement> getFinalHash(
    digest: PartialDigest,
    cHat: List<GroupElement>,
    t: ZKPt<GroupElement>,
    group: CyclicGroup<GroupElement>
): BigInteger =
    digest.continueUniformHash(group.order) {
        val N = t.tHat.size
        for (i in 0 until N) {
            digest(group.asBytes(cHat[i]))
        }
        digest(group.asBytes(t.t1))
        digest(group.asBytes(t.t2))
        digest(group.asBytes(t.t3))
        for (i in t.t4y.indices) {
            digest(group.asBytes(t.t4x[i]))
            digest(group.asBytes(t.t4y[i]))
        }
        for (i in 0 until N) {
            digest(group.asBytes(t.tHat[i]))
        }
    }
