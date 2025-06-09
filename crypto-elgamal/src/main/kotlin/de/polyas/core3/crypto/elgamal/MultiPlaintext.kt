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

import java.math.BigInteger

/**
 * A list of big integers representing a long plaintext message.
 */
data class MultiPlaintext(
    val plaintexts: List<BigInteger>
) {
    constructor(n: Int, generator: (Int) -> BigInteger) : this(List(n, generator))

    fun size(): Int = plaintexts.size

    operator fun get(i: Int): BigInteger = plaintexts[i]
}
