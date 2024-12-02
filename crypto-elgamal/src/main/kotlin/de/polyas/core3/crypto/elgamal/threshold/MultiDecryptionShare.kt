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

import de.polyas.core3.crypto.annotation.Doc

@Doc("A decryption share with an appropriate zero-knowledge proof, computed by a decryption teller in a threshold decryption scheme for a multi-ciphertext")
data class MultiDecryptionShare<GroupElement>(
    @get:Doc("A list of decryption shares, each for one ciphertext of a multi-ciphertext")
    val decryptionShares: List<DecryptionShare<GroupElement>>
)
