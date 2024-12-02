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

/** Parameters of a threshold system */
data class ThresholdConfig(
    /** The threshold */
    val t: Int,

    /** The (total) number of tellers */
    val n: Int
) {
    init {
        require (n >= 1 && t >= 1 && n >= t) {
            "Illegal Parameter for Setup of ElGamal Crypto Threshold System. n=$n, t=$t"
        }
    }
}
