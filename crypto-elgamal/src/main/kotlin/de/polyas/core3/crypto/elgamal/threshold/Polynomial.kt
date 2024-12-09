package de.polyas.core3.crypto.elgamal.threshold

import de.polyas.core3.crypto.elgamal.CyclicGroup
import de.polyas.core3.crypto.annotation.Doc
import de.polyas.core3.crypto.std.SRNG
import java.math.BigInteger

@Doc("A polynomial (used for secret sharing schemes), given as a list of integer coefficients")
data class Polynomial<GroupElement>(
    @property:Doc("List of the polynomial coefficients")
    val coefficients: List<BigInteger>
) {

    /**
     * Computes the sequence of blinded coefficients g^c, for c in coefficients,
     * where g is the generator of the given cyclic [group].
     */
    fun blindPolynomial(group: CyclicGroup<GroupElement>): List<GroupElement> =
        coefficients.map { group.powerOfG(it) }

    /**
     * Evaluates the polynomial in the given point [x]. The computations are carried out
     * modulo `group.order`.
     */
    fun valueAt(group: CyclicGroup<GroupElement>, x: BigInteger): BigInteger =
        coefficients.foldRight(BigInteger.ZERO) { coefficient, partialResult ->
            (partialResult * x + coefficient).mod(group.order)
        }

    /**
     * Evaluates the polynomial in the given point [x]. The computations are carried out
     * modulo `group.order`.
     */
    fun valueAt(group: CyclicGroup<GroupElement>, x: Int): BigInteger =
        valueAt(group, BigInteger.valueOf(x.toLong()))

    companion object {

        /**
         * Generates a random polynomial with the given [numberOfCoefficients] over the given cyclic [group].
         */
        fun <GroupElement> random(numberOfCoefficients: Int, group: CyclicGroup<GroupElement>): Polynomial<GroupElement> {
            val coefficients = List(numberOfCoefficients) { index ->
                when (index) {
                    (numberOfCoefficients - 1) -> SRNG.nextBigIntInRange(BigInteger.ONE, group.order)
                    else -> SRNG.nextBigIntInRange(BigInteger.ZERO, group.order)
                }
            }
            return Polynomial(coefficients)
        }

        /**
         * Generates a random polynomial with `config.t` coefficients over the given cyclic [group].
         */
        fun <GroupElement> random(config: ThresholdConfig, group: CyclicGroup<GroupElement>): Polynomial<GroupElement> =
            random(config.t, group)
    }
}
