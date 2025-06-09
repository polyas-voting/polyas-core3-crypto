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

@Doc("The t-components of a zero-knowledge proof of correct shuffle")
data class ZKPt<GroupElement>(
    @get:JsonProperty("t1") val t1: GroupElement,
    @get:JsonProperty("t2") val t2: GroupElement,
    @get:JsonProperty("t3") val t3: GroupElement,
    @get:JsonProperty("t4y") val t4y: List<GroupElement>,
    @get:JsonProperty("t4x") val t4x: List<GroupElement>,
    @get:JsonProperty("tHat") val tHat: List<GroupElement>
)
