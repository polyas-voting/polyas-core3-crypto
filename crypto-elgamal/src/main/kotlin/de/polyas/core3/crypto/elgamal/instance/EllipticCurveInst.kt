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

import de.polyas.core3.crypto.elgamal.CyclicGroup
import de.polyas.core3.crypto.std.KDF.numbersFromSeed
import de.polyas.core3.crypto.std.buildByteArray
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve
import java.math.BigInteger

/**
 * An instance of [CyclicGroup] backed by an elliptic curve group.
 *
 * We use the secp256k1 curve. Unlike secp256r1 and others, it has a very
 * simple structure making it very efficient and very few options which could
 * be abused to backdoor the system.
 *
 * The system description is given in the following publication
 * [http://www.secg.org/sec2-v2.pdf](http://www.secg.org/sec2-v2.pdf).
 */
class EllipticCurveInst : CyclicGroup<ECElement> {

    override val order: BigInteger = curve.order

    override fun messageUpperBound(): BigInteger = P.divide(kBI)

    override val identity: ECElement = infinity

    override val generator: ECElement get() = groupGenerator

    override operator fun ECElement.times(other: ECElement): ECElement =
        ECElement(this.point().add(other.point()))

    override infix fun ECElement.pow(exponent: BigInteger): ECElement {
        val normalizedExponent = if (exponent < BigInteger.ZERO) exponent.mod(order) else exponent
        return ECElement(this.point().multiply(normalizedExponent))
    }

    override fun inverse(a: ECElement): ECElement =
        ECElement(a.point().negate())

    /**
	 * Implements the Koblitz method for encoding into a curve
	 * [https://pdfs.semanticscholar.org/c7c5/47ede2da32aba645edb11e33f1d32af735e2.pdf](https://pdfs.semanticscholar.org/c7c5/47ede2da32aba645edb11e33f1d32af735e2.pdf),
	 * [http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.444.1768&rep=rep1&type=pdf](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.444.1768&rep=rep1&type=pdf)
	 *
	 * With overwhelming probability in k (or at least really big) at least one of the k x-coordinates will be on the curve.
	 *
	 * The downside is the message space is limited to q/k rather than the order of the group.
	 *
	 * @see CyclicGroup.encode
	 */
    override fun encode(a: BigInteger): ECElement {
        require(!(a.signum() < 0 || a > P.divide(kBI))) { "Message is negative or too large to be safely encoded" }
        for (i in 1..k) {
            val x = a.multiply(kBI).add(BigInteger.valueOf(i)).mod(P) // set x = ak + i
            val ySquar = x.pow(3).add(A.multiply(x)).add(B).mod(P)
            //If not y exists then we continue with the next i.
            if (legendreSymbol(ySquar, P).signum() != 1) continue
            val y = curve.fromBigInteger(ySquar).sqrt().toBigInteger() // Solve for y^2= x^3 +  ax + b, y = (x^3+ax+b)^-2
            val point = curve.createPoint(x, y)
            if (point.isValid) return ECElement(point)
        }
        throw IllegalArgumentException("Unable to safely encode this message")
    }

    /**
	 * Implements the Koblitz method for decoding from a curve
	 *
	 * @see CyclicGroup.decode
	 */
    override fun decode(a: ECElement): BigInteger =
        a.point().normalize().affineXCoord.toBigInteger().subtract(BigInteger.ONE).divide(kBI)

    override fun elementsFromSeed(n: Int, seed: String): List<ECElement> =
        List(n) { i: Int -> selectGeneratorVerifiably(seed, 10 + i) }

    /**
     * This implements algorithm A.2.3 Verifiable Canonical Generation of the
     * Generator g from NIST fips186-4
     *
     * @param domainParameterSeed The seed used to generate
     * @param index The index for the generator to be created
     * @return Infinity is returned on error otherwise the generator
     */
    private fun selectGeneratorVerifiably(domainParameterSeed: String, index: Int): ECElement {
        val seed = buildByteArray {
            put(domainParameterSeed)
            put(0x6767656E)
            put(index)
        }

        val point = numbersFromSeed(P.multiply(BigInteger.valueOf(2)), seed)
            .map { w: BigInteger ->
                val x = w.mod(P)
                val ySquar = x.pow(3).add(A.multiply(x)).add(B).mod(P)
                //We check to make sure that a y exists, if not we return infinity (which is filtered out)
                if (legendreSymbol(ySquar, P).signum() != 1) return@map curve.infinity
                val y = curve.fromBigInteger(ySquar).sqrt().toBigInteger()
                val finalY = if (w < P) P.subtract(y).mod(P) else y
                curve.createPoint(x, finalY)
            }
            .first { g: ECPoint -> !g.isInfinity && g.isValid }
        return ECElement(point)
    }

    override fun validGroupElement(a: ECElement): Boolean = a.point().isValid

    override fun asBytes(groupElement: ECElement): ByteArray = groupElement.asBytes()

    override fun asCanonicalString(groupElement: ECElement): String = groupElement.asHexString()

    override fun fromBytes(bytes: ByteArray): ECElement? {
        val a = curve.decodePoint(bytes)
        return if (a.isValid) ECElement(a) else null
    }

    companion object {
        internal val curve = SecP256K1Curve()
        private val group: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
        private val infinity = ECElement(curve.infinity)
        private val groupGenerator = ECElement(group.g)
        private val A: BigInteger = curve.a.toBigInteger()
        private val B: BigInteger = curve.b.toBigInteger()
        private val P: BigInteger = curve.q // the order of the underlying field
        private const val k = 80L
        private val kBI: BigInteger = BigInteger.valueOf(k)
    }
}
