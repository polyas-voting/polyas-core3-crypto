/*
 * Copyright 2025 Polyas GmbH
 *
 * Licensed under GNU Affero General Public License v3.0; you may not use
 * this file except in compliance with the License. You may obtain a copy of
 * the License at https://www.gnu.org/licenses/agpl-3.0.en.html.
 * This software is distributed WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
 * either express or implied.
 */
package de.polyas.core3.crypto.elgamal.shuffle.wikstroem

import com.fasterxml.jackson.annotation.JsonProperty
import de.polyas.core3.crypto.annotation.Doc
import java.math.BigInteger

@Doc("The s-components of a zero-knowledge proof of correct shuffle")
data class ZKPs(
    @get:JsonProperty("s1") val s1: BigInteger,
    @get:JsonProperty("s2") val s2: BigInteger,
    @get:JsonProperty("s3") val s3: BigInteger,
    @get:JsonProperty("s4") val s4: List<BigInteger>,
    @get:JsonProperty("sHat") val sHat: List<BigInteger>,
    @get:JsonProperty("sPrime") val sPrime: List<BigInteger>
)
