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

    fun decrypt(secretKey: BigInteger, ciphertext: Ciphertext<GroupElem>): BigInteger =
        with (group) {
            decode(ciphertext.y / (ciphertext.x pow secretKey))
        }

    fun decryptWithoutDecoding(secretKey: BigInteger, ciphertext: Ciphertext<GroupElem>): GroupElem =
        with (group) {
            ciphertext.y / (ciphertext.x pow secretKey)
        }

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
