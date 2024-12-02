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