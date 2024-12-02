package de.polyas.core3.crypto.elgamal.instance

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue
import de.polyas.core3.crypto.annotation.Doc
import org.bouncycastle.math.ec.ECCurve
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve
import org.bouncycastle.util.encoders.Hex

/**
 * A point of the elliptic curve SecP256K1Curve. It encapsulates the Bouncy Castle's [ECPoint]
 * and provides JSON serialization/deserialization, as well as some conversions.
 */
@Doc("A point of the elliptic curve SecP256K1")
class ECElement internal constructor(
    private val point: ECPoint
) {
    fun point() : ECPoint = point

    fun asBytes(): ByteArray =
        point.getEncoded(true)

    @JsonValue
    fun asHexString(): String =
        Hex.toHexString(point.getEncoded(true))

    override fun toString(): String =
        asHexString()

    override fun equals(other: Any?): Boolean =
        other is ECElement && point.equals(other.point)

    override fun hashCode(): Int = point.hashCode()

    companion object {
        val curve: ECCurve.AbstractFp = SecP256K1Curve()

        fun fromECPoint(point: ECPoint) : ECElement {
            require (point.isValid)
            return ECElement(point)
        }

        fun fromBytes(bytes: ByteArray) : ECElement =
            fromECPoint(curve.decodePoint(bytes))

        @JvmStatic @JsonCreator
        fun fromHexString(hexString: String) : ECElement {
            val bytes = Hex.decode(hexString)
            return fromBytes(bytes)
        }
    }
}