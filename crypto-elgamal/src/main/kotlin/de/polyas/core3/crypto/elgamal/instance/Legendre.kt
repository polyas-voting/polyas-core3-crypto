package de.polyas.core3.crypto.elgamal.instance

import java.math.BigInteger
import java.math.BigInteger.ONE
import java.math.BigInteger.TWO

/**
 * Computes the Legendre symbol (a/p) which is:
 * * +1 if a is a quadratic residue modulo p and a != 0 (mod p)
 * * -1 if a is a quadratic non-residue module p
 * *  0 if a == 0 (mod p)
 *
 * An integer a is a _quadratic residue modulo n_, if a = x*x (mod q) for some x.
 *
 * The computational cost of computing the Legendre symbol is one modular exponentiation.
 */
internal fun legendreSymbol(a: BigInteger, p: BigInteger): BigInteger {
    val q = (p - ONE)/TWO
    val ls = a.modPow(q, p)
    return if (ls == (p - ONE)) MINUS_ONE else ls
}

private val MINUS_ONE = BigInteger.valueOf(-1)
