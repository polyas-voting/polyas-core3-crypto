package de.polyas.core3.crypto.elgamal.shuffle.wikstroem

import de.polyas.core3.crypto.std.GuardedSRNG
import java.util.*

/**
 * A permutation for the zero knowledge proof (HLKD17).
 */
class Permutation(
    private val permutation: IntArray
) {
    private val inverse: IntArray = inverse(permutation)

    fun size(): Int = permutation.size

    /** The [i]-th element of the permutation (a number in the range [0..N)) */
    operator fun get(i: Int): Int = permutation[i]

    /** Returns the value mapped by the inverse of this permutation. */
    fun getInv(j: Int): Int = inverse[j]

    /**
     * Applies this permutation to the given list of values.
     */
    fun <A> applyTo(values: List<A>): List<A> {
        require(values.size == size())
        return List(size()) { i -> values[getInv(i)] }
    }

    companion object {

        fun random(size: Int): Permutation =
            Permutation(randomPermutationAsArray(size))

        /**
         * Generates a random permutation of size N.
         *
         * Algorithm 4.2 of (HLDK17), essentially Knuth’s shuffle algorithm.
         *
         * @param N the size of the permutation
         * @return A random permutation of size N
         */
        private fun randomPermutationAsArray(N: Int): IntArray {
            val I = IntArray(N) { i -> i }
            val J = IntArray(N) // all zeros
            GuardedSRNG.use { rnd: Random ->
                for (i in 0 until N) { //i in <0,...,N-1>
                    val k = rnd.nextInt(N - i) + i //k in <i,...,N-1>
                    J[i] = I[k]
                    I[k] = I[i]
                }
            }
            return J
        }

        private fun inverse(permutation: IntArray): IntArray {
            val inverse = permutation.mapIndexed { index, value -> value to index }
                .associate { it }
            return IntArray(permutation.size) { i -> inverse[i]!! }
        }
    }
}
