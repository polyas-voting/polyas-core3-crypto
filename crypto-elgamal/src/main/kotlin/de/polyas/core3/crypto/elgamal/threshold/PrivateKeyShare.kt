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
import java.math.BigInteger

/**
 * A private key share for the ElGamal threshold system.
 */
@Doc("A private key share for the ElGamal threshold decryption")
data class PrivateKeyShare<out GroupElement>(
    @property:Doc("The index of the teller holding the key share")
    val nr: Int,

    @property:Doc("The private key share")
    val keyShare: BigInteger,

    @property:Doc("The commitment (that is the corresponding public key share) published during the key establishing protocol")
    val commitment: GroupElement
)
