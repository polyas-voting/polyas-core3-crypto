package de.polyas.core3.crypto.elgamal.zkp

import com.fasterxml.jackson.annotation.JsonProperty
import de.polyas.core3.crypto.elgamal.CyclicGroup
import de.polyas.core3.crypto.elgamal.VerificationResult
import de.polyas.core3.crypto.std.GuarderSRNG
import java.math.BigInteger

/**
 * Zero-knowledge proof of equality of discrete logarithms. Instances of class
 * [InteractiveProver] can be used for interactive or non-interactive protocol execution.
 * Class [Verifier] implements methods challenge and verify for the interactive case.
 *
 * @see EqlogNIZKP
 */
object EqlogZKP {

    data class Statement<GroupElement>(
        @get:JsonProperty("baseX")  val baseX: GroupElement,
        @get:JsonProperty("baseY")  val baseY: GroupElement,
        @get:JsonProperty("X")      val X: GroupElement,
        @get:JsonProperty("Y")      val Y: GroupElement
    )

    data class InitialMessage<GroupElement>(
        @get:JsonProperty("A") val A: GroupElement,
        @get:JsonProperty("B") val B: GroupElement
    )

    /**
     * A session of the prover.
     *
     * Method [finalMessage] of this instance should not be used for more than one challenge.
     */
    class InteractiveProver<GroupElement>(
        private val group: CyclicGroup<GroupElement>,
        private val statement: Statement<GroupElement>,
        private val witness: BigInteger
    ) {
        /**
         * The blinding factor, sampled at random on this instance creation.
         */
        private val a: BigInteger = GuarderSRNG.nextBigInt(group.order)

        /**
         * The initial message (derived from the blinding factor [a]).
         */
        val initialMessage: InitialMessage<GroupElement> = with(group) {
            InitialMessage(statement.baseX pow a, statement.baseY pow a)
        }

        /**
         * Computes the final message for the encapsulated initial message and the given [challenge].
         */
        fun finalMessage(challenge: BigInteger): BigInteger =
            (a + challenge * witness).mod(group.order)
    }

    class Verifier<GroupElement>(
        private val group: CyclicGroup<GroupElement>,
        private val statement: Statement<GroupElement>
    ) {
        /**
         * Returns a (random) challenge.
         */
        fun challenge(): BigInteger = GuarderSRNG.nextBigInt(group.order)

        /**
         * Verifies validity of the ZKP for the obtained before initial message and
         * the given final message.
         */
        fun verify(
            initialMsg: InitialMessage<GroupElement>,
            challenge: BigInteger,
            finalMsg: BigInteger
        ): VerificationResult =
            with(group) {
                val expectedA = (statement.baseX pow finalMsg) / statement.X.pow(challenge)
                val expectedB = (statement.baseY pow finalMsg) / (statement.Y pow challenge)

                when {
                    (expectedA != initialMsg.A) -> VerificationResult.Failed("EqLogZKP: A has invalid value")
                    (expectedB != initialMsg.B) -> VerificationResult.Failed("EqLogZKP: B has invalid value")
                    else -> VerificationResult.Correct
                }
            }
    }
}