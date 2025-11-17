/*
 * Copyright 2025 Polyas GmbH
 *
 * Licensed under GNU Affero General Public License v3.0; you may not use
 * this file except in compliance with the License. You may obtain a copy of
 * the License at https://www.gnu.org/licenses/agpl-3.0.en.html.
 * This software is distributed WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
 * either express or implied.
 */
package de.polyas.core3.crypto.elgamal.threshold

import de.polyas.core3.crypto.elgamal.*
import de.polyas.core3.crypto.elgamal.threshold.Polynomial.Companion.random
import de.polyas.core3.crypto.elgamal.zkp.DlogNIZKP
import de.polyas.core3.crypto.elgamal.zkp.EqlogNIZKP
import de.polyas.core3.crypto.elgamal.zkp.EqlogZKP
import java.math.BigInteger

/**
 * Threshold decryption. Provides methods for distributed key generation (via
 * the inner class KeyGen) and for using and combining public and private key shares.
 *
 * In the protocol, each teller distributes its share of the secret with the others through a
 * Feldman VSS scheme (as referenced above). In our implementation, if any of
 * the tellers detects any error, the protocol is aborted. Because of this, it is
 * fine to use the above-mentioned protocol (otherwise, if we wanted to handle
 * errors and recover from them, we would need to use a more complicated
 * protocol based, for instance, on Pederson VSS, such as used in Civitas).
 *
 * @param config The configuration of the threshold system
 * @param group The cyclic group over which the computations are carried out
 */
class ThresholdDecryption<GroupElem>(
    val config: ThresholdConfig,
    val group: CyclicGroup<GroupElem>
) : CyclicGroup<GroupElem> by group {

    /**
     * Returns a new key generation object for the teller with the given number [tellerIndex].
     */
    fun newKeyGen(tellerIndex: Int): Teller = Teller(tellerIndex)

    /**
     * Combines public key contributions into the combined public encryption key. The returned
     * encryption key is simply a product of the provided values (modulo p).
     *
     * A _public key contribution_ of a teller is the factor of index 0 of this teller,
     * that is the value `g^{p[0]}`, where `p[0]` is the 0-th coefficient
     * of the polynomial of this teller.
     *
     * @param publicKeyShares List of public key contributions provided by all the tellers
     * @return The combined public encryption key
     */
    fun publicKeyFromContributions(publicKeyShares: Collection<GroupElem>): GroupElem {
        require (publicKeyShares.size == config.n) { "Invalid number ${publicKeyShares.size} of public key shares" }
        return publicKeyShares.product()
    }

    /**
     * Returns the public key share of the [i]-th teller, computed from the blinded coefficients.
     */
    fun publicKeyShareFromBlindedCoefficients(blindedCoefficients: Collection<List<GroupElem>>, i: Int): GroupElem {
        val tellerIndex = BigInteger.valueOf((i + 1).toLong())
        return blindedCoefficients.asSequence().map { coefficients: List<GroupElem> ->
            // evaluation in the exponents of the polynomial (given by the blindedCoefficients) at tellerIndex
            (config.t - 1 downTo 0).fold(group.identity) { prod, j ->
                 coefficients[j] * (prod pow tellerIndex)
            }
        }
        .product()
    }

    /**
     * Applies the given private key share to the given ciphertext and returns the
     * resulting decryption share along with a zero-knowledge proof of correctness
     * of this operation.
     *
     * @param keyShare
     * The private key share along with the commitment to it.
     * @param cipherText
     * Ciphertext to be decrypted
     *
     * @return Decryption share along with a zero-knowledge proof.
     */
    fun decryptionShare(
        keyShare: PrivateKeyShare<GroupElem>,
        cipherText: Ciphertext<GroupElem>
    ): DecryptionShare<GroupElem> {
        val partialDecryption: GroupElem = cipherText.x pow keyShare.keyShare
        val eqlogNIZKP = EqlogNIZKP(group)
        val statement = EqlogZKP.Statement(group.generator, cipherText.x, keyShare.commitment, partialDecryption)
        val proof = eqlogNIZKP.createProof(statement, keyShare.keyShare)
        return DecryptionShare(keyShare.nr, partialDecryption, proof)
    }

    /**
     * Verifies the zero knowledge proof of correct decryption shares of a
     * multi-ciphertext.
     */
    fun verifyDecryptionShareZKP(
        ciphertext: MultiCiphertext<GroupElem>,
        decrShare: MultiDecryptionShare<GroupElem>,
        publicKeyShare: GroupElem
    ): VerificationResult {
        for (i in ciphertext.ciphertexts.indices) {
            val partialDecryption = decrShare.decryptionShares[i]
            verifyDecryptionShareZKP(partialDecryption, ciphertext.ciphertexts[i], publicKeyShare) onFailure { return it }
        }
        return VerificationResult.Correct
    }

    /**
     * Verifies the zero knowledge proof of correct decryption share.
     */
    fun verifyDecryptionShareZKP(
        decryptionShare: DecryptionShare<GroupElem>,
        ciphertext: Ciphertext<GroupElem>,
        publicKeyShare: GroupElem
    ): VerificationResult {
        val eqlogNIZKP = EqlogNIZKP(group)
        val statement = EqlogZKP.Statement(group.generator, ciphertext.x, publicKeyShare, decryptionShare.decShare)
        val zkp = decryptionShare.zkp
        return eqlogNIZKP.verify(statement, zkp)
    }

    /**
     * Combines the given decryption shares to finalize decryption.
     *
     * @param ciphertext
     * The ciphertext to be decrypted. It is assumed that the given
     * decryption shares were produced for this ciphertext.
     * @param decryptionShares
     * Decryption shares of (at least t) tellers for the given
     * ciphertext.
     *
     * @return The decrypted plaintext.
     */
    fun finalizeDecryption(
        ciphertext: Ciphertext<GroupElem>,
        decryptionShares: List<DecryptionShare<GroupElem>>
    ): BigInteger =
        group.decode(finalizeDecryptionUnmapped(ciphertext, decryptionShares))

    /**
     * Combines the given decryption shares to finalize decryption without applying
     * the final unmapping from the group G into plaintext.
     *
     * @param ciphertext
     * The ciphertext to be decrypted. It is assumed that the given
     * decryption shares were produced for this ciphertext.
     * @param decryptionShares
     * Decryption shares of (at least t) tellers for the given
     * ciphertext.
     * @return The decrypted plaintext as an element of the group G.
     */
    private fun finalizeDecryptionUnmapped(
        ciphertext: Ciphertext<GroupElem>,
        decryptionShares: List<DecryptionShare<GroupElem>>
    ): GroupElem {
        val s = combineDecryptionShares(decryptionShares)
        return ciphertext.y * group.inverse(s)
    }

    private fun combineDecryptionShares(decryptionShares: List<DecryptionShare<GroupElem>>): GroupElem {
        require(decryptionShares.size >= config.t)
            { "The number of decryption shares (${decryptionShares.size}) must not be smaller than the threshold (${config.t})" }

        val indices: Collection<Int> = decryptionShares.map { it.nr }

        indices.forEach{ n ->
            require(n >= 1 && n <= config.n) { "The indices of the decryption shares must be in the range [1,..N]" }
        }
        require (indices.size == indices.toSet().size) { "The set of indices of the decryption shares has duplicates" }

        return decryptionShares.productOf { share: DecryptionShare<GroupElem> ->
            share.decShare pow lagrange(indices, share.nr)
        }
    }

    private fun lagrange(servernumbers: Collection<Int>, j: Int): BigInteger {
        val numerator = servernumbers.asSequence()
            .filter { l -> l != j }
            .map { l -> l.toLong() }
            .fold(1L) { x, y -> x * y }
        val denominator = servernumbers.asSequence()
            .filter { l -> l != j }
            .map { l -> (l - j).toLong() }
            .fold(1L) { x, y -> x * y }
        return (BigInteger.valueOf(numerator) * BigInteger.valueOf(denominator).modInverse(order)).mod(order)
    }

    /**
     * Object representing one participant (a teller) in the multi-party key generation for
     * threshold decryption scheme, with the number [nr].
     *
     * This object provides all the data to be shared (exchanged) with the
     * remaining tellers. When the corresponding data of the remaining tellers is
     * gathered, you can call method `finalize` to finalize the process and
     * produce the private key share of this teller.
     *
     * We assume here that all the tellers must behave honestly during the key
     * generation process. If this is not the case the process is aborted.
     *
     * @param nr The index of this teller
     * @param polynomial The polynomial of this teller; a random one is generated if not provided.
     */
    inner class Teller(
        val nr: Int,
        private val polynomial: Polynomial<GroupElem> = random(config, group)
    ) {

        /**
         * Blinded coefficients of the encapsulated polynomial, that is the values
         *
         *     g^polynomial[0], ..., g^polynomial[t].
         *
         * This list is meant to be made public (so that, in particular, all the remaining
         * tellers can obtain it).
         */
        val blindedCoefficients: List<GroupElem> = polynomial.blindPolynomial(group)

        /**
         * Non-interactive zero-knowledge proofs of knowledge of the discrete logarithms of the [blindedCoefficients]
         * (which are the coefficients of the [polynomial]).
         */
        val pkCoefficients: List<DlogNIZKP.Proof> = proofsOfKnowledgeOfCoefficient()

        private fun proofsOfKnowledgeOfCoefficient(): List<DlogNIZKP.Proof> {
            val coefficients = polynomial.coefficients
            require(coefficients.size == blindedCoefficients.size)
                { "Incorrect number of coefficient commitments: ${coefficients}; expected is ${blindedCoefficients.size}" }

            val dlogNIZKP = DlogNIZKP(group)

            return coefficients.indices.map { i ->
                dlogNIZKP.createProof(blindedCoefficients[i], coefficients[i])
            }
        }

        /**
         * The value of the polynomial of this teller at the point i. This value is
         * meant to be sent (using a confidential channel) to the i-th teller.
         */
        fun polynomialAt(i: Int): BigInteger = polynomial.valueAt(group, i)

        /**
         * Data to be shared with the i-th teller. It contains both the value of the
         * polynomial at the point i (which is confidential information specifically
         * meant for the i-th teller) and the blinded coefficients (which is public
         * information).
         */
        fun dataSharedWith(i: Int): KeyGenSharedData<GroupElem> =
            KeyGenSharedData(nr, polynomialAt(i), blindedCoefficients, pkCoefficients)

        /**
         * Accepts data produced by the remaining tellers and either reports an error
         * (if this data is not as expected) or produces the private decryption share of
         * this teller.
         *
         * @param sharedData
         * list of records shared by all the remaining tellers
         */
        fun finalize(sharedData: List<KeyGenSharedData<GroupElem>>): FinalisationResult<GroupElem> {
            proofsCorrect(sharedData) onFailure { return FinalisationResult.Error(it.errorMessage) }
            sharesCorrect(sharedData) onFailure { return FinalisationResult.Error(it.errorMessage) }
            return FinalisationResult.Success(computeKeyShare(sharedData))
        }

        /**
         * Computes the secret key share of this teller.
         */
        private fun computeKeyShare(sharedData: List<KeyGenSharedData<GroupElem>>): PrivateKeyShare<GroupElem> {
            val sk = sharedData.sumOf { it.point } // the sum of the points provided by other tellers
                .add(polynomialAt(nr)) // plus the point of this teller
                .mod(group.order) // modulo the group order
            val pk = group.powerOfG(sk) // the public key share
            return PrivateKeyShare(nr, sk, pk)
        }

        private fun proofsCorrect(sharedData: List<KeyGenSharedData<GroupElem>>): VerificationResult {
            val dlogNIZKP = DlogNIZKP(group)
            for (data in sharedData) {
                VerificationResult.expect(data.blindedCoefficients.size != data.pkCoefficients.size) {
                    "The number of coefficient commitments doest not match the number of proofs in data from ${data.producer}"
                }
                for (i in data.blindedCoefficients.indices) {
                    dlogNIZKP.verify(data.blindedCoefficients[i], data.pkCoefficients[i])
                        .onFailure { return it.mapErrorMessage { msg -> "Wrong data from ${data.producer}: $msg" } }
                }
            }
            return VerificationResult.Correct
        }

        private fun sharesCorrect(sharedData: List<KeyGenSharedData<GroupElem>>): VerificationResult {
            // Check that the shares come from  n - 1 distinct producers
            val producerSet = sharedData.asSequence()
                .map(KeyGenSharedData<GroupElem>::producer)
                .toSet()
            if (sharedData.size != producerSet.size) {
                return VerificationResult.Failed("Duplicate share record")
            }
            if (sharedData.size != config.n - 1) {
                return VerificationResult.Failed("Number of shared records should be ${config.n - 1}. Only ${sharedData.size} given")
            }

            // Check that each share is correct
            for (sh in sharedData) {
                shareCorrect(sh) onFailure { return it }
            }

            return VerificationResult.Correct
        }

        private fun shareCorrect(sharedData: KeyGenSharedData<GroupElem>): VerificationResult {
            val producerIndex = sharedData.producer
            if (nr == producerIndex) {
                return VerificationResult.Failed("Threshold teller does not accept data from himself")
            }

            if (producerIndex < 0 || producerIndex > config.n) {
                return VerificationResult.Failed("Invalid teller index $producerIndex in the given shared data")
            }

            val factors = sharedData.blindedCoefficients
            return when {
                config.t != factors.size
                    -> VerificationResult.Failed("degree of shared polynomial should be ${config.t - 1}. teller=$nr, misbehaving teller=$producerIndex")

                !dataOfAnotherTellerIsCorrect(sharedData.point, factors)
                    -> VerificationResult.Failed("Couldn't verify shared TS value. teller = $nr, misbehaving teller = $producerIndex")

                else -> VerificationResult.Correct
            }
        }

        private fun dataOfAnotherTellerIsCorrect(sharedValue: BigInteger, factors: List<GroupElem>): Boolean {
            // evaluate in the exponent the value of the polynomial with the given factors (blinded coefficients) in the point nr
            val rhs: GroupElem = factors.indices.productOf { j: Int ->
                    val bf = factors[j]
                    val iPowL = BigInteger.valueOf(nr.toLong()).pow(j) // nr^j
                    bf pow iPowL
                }

            val lhs = group.powerOfG(sharedValue)
            return (lhs == rhs)
        }
    }

    sealed class FinalisationResult<out G> {
        data class Success<G>(val privateKeyShare: PrivateKeyShare<G>): FinalisationResult<G>()
        data class Error(val errorMessage: String): FinalisationResult<Nothing>()

        inline fun getOrElse(onError: (errorMessage:String) -> Nothing): PrivateKeyShare<G> = when (this) {
            is Success -> privateKeyShare
            is Error -> onError(errorMessage)
        }
    }
}
