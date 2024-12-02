/*
 * Copyright 2025 Polyas GmbH
 *
 * Licensed under GNU Affero General Public License v3.0; you may not use
 * this file except in compliance with the License. You may obtain a copy of
 * the License at https://www.gnu.org/licenses/agpl-3.0.en.html.
 * This software is distributed WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
 * either express or implied.
 */
package de.polyas.core3.crypto.elgamal.instance

import com.fasterxml.jackson.annotation.JsonProperty
import de.polyas.core3.crypto.elgamal.CyclicGroup
import de.polyas.core3.crypto.elgamal.instance.SchnorrGroup.Companion.ModPower
import de.polyas.core3.crypto.std.KDF
import de.polyas.core3.crypto.std.buildByteArray
import java.math.BigInteger
import java.math.BigInteger.ONE

/**
 * A Schnorr group with k=2, that is a group of quadratic residues modulo a safe
 * prime p = 2q + 1, where q is also a prime. Such a group is suitable for
 * ElGamal-based cryptography.
 */
class SchnorrGroup(
    /** The modulus */
    @get:JsonProperty("p") val p: BigInteger,

    /** The group order */
    @get:JsonProperty("q") val q: BigInteger,

    /** The generator */
    @get:JsonProperty("g") val g: BigInteger
) : CyclicGroup<BigInteger> {

    constructor(q: BigInteger, g: BigInteger) : this(p = (q.shiftLeft(1) + ONE), q, g)

    override val order: BigInteger = q

    override val identity: BigInteger = ONE

    override val generator: BigInteger = g

    override operator fun BigInteger.times(other: BigInteger): BigInteger = this.multiply(other).mod(p)

    override infix fun BigInteger.pow(exponent: BigInteger): BigInteger {
        val normalizedExponent = if (exponent < BigInteger.ZERO) exponent.mod(order) else exponent
        return modPow(this, normalizedExponent, p)
    }

    override fun inverse(a: BigInteger): BigInteger = a.modInverse(p)

    override fun encode(a: BigInteger): BigInteger {
        val x = a + ONE
        return if (isQuadraticResidue(x)) x else (p - x)
    }

    override fun decode(a: BigInteger): BigInteger =
        if (a <= q) (a - ONE)
        else (p - a - ONE)

    override fun elementsFromSeed(n: Int, seed: String): List<BigInteger> =
        List(n) { i: Int -> selectGeneratorVerifiably(seed, 10 + i) }

    override fun validGroupElement(a: BigInteger): Boolean =
        a >= ONE && a < p && isQuadraticResidue(a)

    override fun asBytes(groupElement: BigInteger): ByteArray = groupElement.toByteArray()

    override fun asCanonicalString(groupElement: BigInteger): String = groupElement.toString()

    override fun messageUpperBound(): BigInteger = q

    override fun toString(): String = "ElGamal[p=$p q=$q with g=$g]"

    override fun hashCode(): Int {
        val prime = 31
        var result = 1
        result = prime * result + g.hashCode()
        result = prime * result + p.hashCode()
        result = prime * result + q.hashCode()
        return result
    }

    override fun equals(other: Any?): Boolean {
        if (other !is SchnorrGroup) return false
        if (other === this) return true
        return g == other.g && p == other.p && q == other.q
    }

    override fun fromBytes(bytes: ByteArray): BigInteger? {
        val a = BigInteger(bytes)
        return a.takeIf { validGroupElement(a) }
    }

    private fun isQuadraticResidue(x: BigInteger): Boolean =
        modPow(x, q, p) == ONE

    /**
     * This implements algorithm A.2.3 Verifiable Canonical Generation of the
     * Generator g from NIST fips186-4
     *
     * Given an acceptable [domainParameterSeed] this produces generators
     * in a verifiable way (that is in a reproducible way).
     *
     * There is one point where this implementation differs from the
     * standard: this method returns generators which are distributed
     * "pseudo-uniformly" in the group. Technically: the values W which exceed p
     * are discarded.
     *
     * @param domainParameterSeed The seed used to generate
     * @param index The index for the generator to be created
     */
    private fun selectGeneratorVerifiably(domainParameterSeed: String, index: Int): BigInteger {
        val e = TWO
        val seed = buildByteArray {
            put(domainParameterSeed)
            put(0x6767656E)
            put(index)
        }
        return KDF.numbersFromSeed(p, seed)
            .map { w: BigInteger -> w.modPow(e, p) } // g = w^e (mod p)
            .first { it >= BigInteger.TWO }
    }

    companion object {
        internal fun interface ModPower {
            fun modPow(base: BigInteger, exponent: BigInteger, modulus: BigInteger): BigInteger
        }

        private val modPowImpl: ModPower = ModPower { b, e, n -> b.modPow(e, n) }

        /**
         * A small, 512-bit group for testing purposes.
         */
        val group512 = SchnorrGroup(
            BigInteger("6665979683086439656780172509761187363161553184092846650817239557370140621050056350258393166469163856245812754684765223849227225731102340109106420327579553"),
            BigInteger("2769343681670771180052832017602115669648338337053642363730245126608822487259258583245331911940626904539233796336297243417759515429921893471982103653706198")
        )
        private val TWO = BigInteger("2")

        /**
         * 1536-bit ElGamal group defined in RFC 3526.
         */
		val group1536 = SchnorrGroup(
            BigInteger(
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
                16
            ).subtract(ONE).divide(TWO),
            TWO
        )

        /**
         * 2048-big ElGamal group defined in RFC 3526.
         */
		val group2048 = SchnorrGroup(
            BigInteger(
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
                16
            ).subtract(ONE).divide(TWO),
            TWO
        )

        /**
         * 3072-big ElGamal group defined in RFC 3526.
         */
        val group3072 = SchnorrGroup(
            BigInteger(
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
                16
            ).subtract(ONE).divide(TWO),
            TWO
        )

        /**
         * Returns predefined ElGamal groups of the given bit length.
         */
		fun group(bits: Bits): SchnorrGroup = when (bits) {
            Bits.BITS_512 -> group512
            Bits.BITS_1536 -> group1536
            Bits.BITS_2048 -> group2048
            Bits.BITS_3072 -> group3072
        }

        /**
         * Calculate (base ^ exponent) % modulus; slower, hardened against timing attacks.
         *
         * NOTE: this method REQUIRES modulus to be odd, due to a crash-bug in libgmp.
         *
         * @param base the base, must be positive
         * @param exponent the exponent
         * @param modulus  the modulus
         * @return (base ^ exponent) % modulus
         * @throws ArithmeticException if modulus is non-positive
         * @throws IllegalArgumentException if modulus is even, base is negative, or exponent is negative
         */
        private fun modPow(base: BigInteger, exponent: BigInteger, modulus: BigInteger): BigInteger =
            modPowImpl.modPow(base, exponent, modulus)
    }

    /**
     * Enumeration of bit lengths of available predefined ElGamal groups.
     */
    enum class Bits {
        BITS_512, BITS_1536, BITS_2048, BITS_3072
    }
}
