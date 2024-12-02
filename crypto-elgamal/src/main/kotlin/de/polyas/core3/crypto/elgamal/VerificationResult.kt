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
