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

import de.polyas.core3.crypto.elgamal.ECIES.decrypt
import de.polyas.core3.crypto.elgamal.ECIES.derivePublicKey
import de.polyas.core3.crypto.elgamal.ECIES.encrypt
import de.polyas.core3.crypto.elgamal.ECIES.freshSecretKey
import de.polyas.core3.crypto.std.Message.Companion.fromHexString
import de.polyas.core3.crypto.std.buildMessage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ECIESTest {
    @Test
    fun encryption() {
        val sk = freshSecretKey()
        val pk = derivePublicKey(sk)
        val message = fromHexString("ff66778866772233445566778899887766443322112233442244990000123300aac7")
        val encrypted = encrypt(pk, message)
        val decrypted = decrypt(sk, pk, encrypted).getOrThrow()
        assertEquals(message, decrypted)
    }

    @Test
    fun `wrong ciphertext`() {
        val sk = freshSecretKey()
        val pk = derivePublicKey(sk)
        val message = fromHexString("ff66778866772233445566778899887766443322112233442244990000123300aac7")

        val encrypted = encrypt(pk, message)
        val modified = buildMessage {
            put(encrypted)
            put("x")
        }
        assertTrue(decrypt(sk, pk, modified).isFailure)
    }
}
