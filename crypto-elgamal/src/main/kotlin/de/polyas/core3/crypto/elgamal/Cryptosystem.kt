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

import de.polyas.core3.crypto.std.SRNG
import java.math.BigInteger

/**
 * An ElGamal cryptosystem, providing algorithms for encryption and decryption, over an
 * abstract cyclic group.
 *
 * @param GroupElem The type of group elements
 */
class Cryptosystem<GroupElem>(val group: CyclicGroup<GroupElem>) {

    fun encrypt(encryptionKey: GroupElem, message: BigInteger): Ciphertext<GroupElem> =
        encryptGroupElement(encryptionKey, group.encode(message))

    fun encrypt(encryptionKey: GroupElem, message: BigInteger, randomCoin: BigInteger): Ciphertext<GroupElem> =
        encryptGroupElement(encryptionKey, group.encode(message), randomCoin)

    fun encryptGroupElement(pk: GroupElem, message: GroupElem): Ciphertext<GroupElem> {
        val r = SRNG.nextBigIntInRange(BigInteger.ONE, group.order)
        return encryptGroupElement(pk, message, r)
    }

    fun encryptGroupElement(encryptionKey: GroupElem, message: GroupElem, randomCoin: BigInteger): Ciphertext<GroupElem> =
        with (group) {
            Ciphertext(powerOfG(randomCoin), (message * (encryptionKey pow randomCoin)))
        }

    /**
     * Decrypts the given [ciphertext] using the [secretKey].
     *
     * @return The decrypted plaintext, or null if the input is incorrect (the ciphertext contains invalid group elements)
     */
    fun decrypt(secretKey: BigInteger, ciphertext: Ciphertext<GroupElem>): BigInteger? {
        if (!isValidCiphertext(ciphertext)) return null
        return with (group) {
            decode(ciphertext.y / (ciphertext.x pow secretKey))
        }
    }

    /**
     * Decrypts the given [ciphertext] using the [secretKey], returning the raw group element
     * without decoding it to a plaintext integer.
     *
     * @return The decrypted group element, or null if the ciphertext contains invalid group elements.
     */
    fun decryptWithoutDecoding(secretKey: BigInteger, ciphertext: Ciphertext<GroupElem>): GroupElem? {
        if (!isValidCiphertext(ciphertext)) return null
        return with (group) {
            ciphertext.y / (ciphertext.x pow secretKey)
        }
    }

    private fun isValidCiphertext(ciphertext: Ciphertext<GroupElem>): Boolean =
        group.validGroupElement(ciphertext.x) && group.validGroupElement(ciphertext.y)

    /**
     * Re-randomizes the given [ciphertext] (encrypted with [encryptionKey]) using the provided [randomCoin].
     */
    fun reRandomize(ciphertext: Ciphertext<GroupElem>, encryptionKey: GroupElem, randomCoin: BigInteger): Ciphertext<GroupElem> =
        with (group) {
            Ciphertext(
                x = ciphertext.x * (generator pow randomCoin),
                y = ciphertext.y * (encryptionKey pow randomCoin)
            )
        }
}
