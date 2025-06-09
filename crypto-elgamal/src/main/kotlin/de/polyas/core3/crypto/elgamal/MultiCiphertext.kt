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

import de.polyas.core3.crypto.annotation.Doc

/**
 * List of ElGamal ciphertexts, representing an encryption of a long message,
 * represented as more than one number in Zq.
 *
 * This data class additionally contains field [auxData] for auxiliary data attached to the ciphertext.
 */
@Doc("List of ElGamal ciphertexts (over the given set of group elements); used to represent an encryption of a message which does not fit into one ciphertext")
data class MultiCiphertext<GroupElement>(
    val ciphertexts: List<Ciphertext<GroupElement>>,
    val auxData: Map<String, String>?
) {
    constructor(size: Int, auxData: Map<String, String>? = null, generator: (Int) -> Ciphertext<GroupElement>)
            : this(List(size, generator), auxData)

    fun size(): Int = ciphertexts.size

    operator fun get(i: Int): Ciphertext<GroupElement> = ciphertexts[i]
}
