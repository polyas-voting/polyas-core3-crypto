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

sealed class VerificationResult {

    data object Correct: VerificationResult()
    data class Failed(val errorMessage: String): VerificationResult()

    inline infix fun onFailure(onFailure: (Failed) -> Unit): VerificationResult {
        if (this is Failed) { onFailure(this) }
        return this
    }

    fun andExpect(condition: Boolean, message: () -> String): VerificationResult =
        when (this) {
            is Failed -> this
            is Correct -> if (condition) Correct else Failed(message())
        }

    companion object {
        fun expect(condition: Boolean, message: () -> String): VerificationResult =
            if (condition) Correct else Failed(message())
    }
}

fun VerificationResult.Failed.mapErrorMessage(newMessage: (oldMessage:String) -> String) =
    VerificationResult.Failed(newMessage(this.errorMessage))