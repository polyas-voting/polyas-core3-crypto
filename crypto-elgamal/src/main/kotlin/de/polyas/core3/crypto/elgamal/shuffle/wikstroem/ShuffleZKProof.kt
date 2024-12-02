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

@Doc("Non-interactive zero-knowledge proof of correct shuffle (Wikstroem et al.)")
data class ShuffleZKProof<GroupElement>(
    @get:JsonProperty("t") val t: ZKPt<GroupElement>,
    @get:JsonProperty("s") val s: ZKPs,
    @get:JsonProperty("c") val c: List<GroupElement>,
    @get:JsonProperty("cHat") val cHat: List<GroupElement>
)
