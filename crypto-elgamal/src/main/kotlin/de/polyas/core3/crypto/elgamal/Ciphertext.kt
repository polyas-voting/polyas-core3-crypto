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

import com.fasterxml.jackson.annotation.JsonProperty
import de.polyas.core3.crypto.annotation.Doc

@Doc("ElGamal ciphertext represented as two group elements x and y")
data class Ciphertext<GroupElement> (
    @get:JsonProperty("x") val x: GroupElement,
    @get:JsonProperty("y") val y: GroupElement
)
