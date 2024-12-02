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

import de.polyas.core3.crypto.elgamal.instance.ECElement
import de.polyas.core3.crypto.elgamal.instance.EllipticCurveInst
import de.polyas.core3.crypto.std.SRNG
import de.polyas.core3.crypto.std.Hashes.sha256
import de.polyas.core3.crypto.std.Message
import de.polyas.core3.crypto.std.SymmetricKey
import de.polyas.core3.crypto.std.buildMessage
import java.math.BigInteger

/**
 * A variant of Elliptic Curve Integrated Encryption Scheme
 */
object ECIES {

    private val group: CyclicGroup<ECElement> = EllipticCurveInst()
    private val order = group.order

    fun freshSecretKey(): BigInteger =
        SRNG.nextBigInt(order)

    fun derivePublicKey(secretKey: BigInteger): ECElement =
        group.powerOfG(secretKey)

    fun encrypt(publicKey: ECElement, message: Message): Message = with (group) {
        val y = SRNG.nextBigInt(order)
        val Y = generator pow y
        val Z = publicKey pow y
        val symKey = deriveSymmetricKey(Y, Z, publicKey)
        val c = symKey.deterministicEncryption(message)

        return buildMessage {
            put(group.asBytes(Y))
            put(c)
        }
    }

    fun decrypt(secretKey: BigInteger, publicKey: ECElement, ciphertext: Message): Result<Message> = runCatching {
        val splitPoint = 33
        val Y = group.fromBytes(ciphertext.slice(0, splitPoint).asBytes()) ?: error("Not a valid group element")
        val c = ciphertext.slice(begin = splitPoint)
        val Z: ECElement = with (group) { Y pow secretKey }
        val symKey = deriveSymmetricKey(Y, Z, publicKey)
        return symKey.deterministicDecryption(c)
    }

    private fun deriveSymmetricKey(Y: ECElement, Z1: ECElement, publicKey: ECElement): SymmetricKey {
        val hash = sha256 {
            digest(group.asBytes(Y))
            digest(group.asBytes(Z1))
            digest(group.asBytes(publicKey))
        }
        return SymmetricKey(hash)
    }
}
