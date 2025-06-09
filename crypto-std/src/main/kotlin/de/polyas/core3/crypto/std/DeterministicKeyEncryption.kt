/*
 * Copyright 2025 Polyas GmbH
 *
 * Licensed under GNU Affero General Public License v3.0; you may not use
 * this file except in compliance with the License. You may obtain a copy of
 * the License at https://www.gnu.org/licenses/agpl-3.0.en.html.
 * This software is distributed WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
 * either express or implied.
 */
package de.polyas.core3.crypto.std

import kotlin.experimental.xor

/**
 * Deterministic encryption and the corresponding decryption algorithms
 * intended to be used in scenarios, where encrypted values are used as keys
 * in a key-value schema (storage, database, etc.).
 *
 * In such scenarios, the encrypted keys are used to index the storage and
 * uniquely identify the underlying, unencrypted data. The encryption must be,
 * therefore, deterministic. As such, it does not provide IND-CCA security.
 * We still want to, however, avoid some of the pitfalls of naively used deterministic
 * encryption. The variant of deterministic encryption used here works as follows.
 *
 * To encrypt a given `payload` under a key `key`, it first computes a SHA-256 hash `h`
 * of the `payload`. Let `mask` denote the byte array of the same length as `payload`,
 * obtained by concatenating `h` with itself as many times as needed and possibly
 * dropping unnecessary last bytes (to end up with the required length).
 * The final result is computed by XOR-ing the payload with `mask`, prepending it
 * with `h`, and then encrypting it with the encapsulated [key] and with all IV:
 *
 *      Enc(h | payload XOR mask(payload))
 *
 * where | denotes byte concatenation and Enc denotes encryption with [key] and zero-IV.
 *
 * Including `h` under the encryption is needed for decryption. XOR-ing the payload with the
 * mask (which depends on the payload) guarantees that each block (before encryption) depends
 * on the whole payload.
 */
class DeterministicKeyEncryption(private val key: SymmetricKey) {

    fun encrypt(payload: Message): Message {
        val hash = Hashes.sha256(payload)
        val maskedPayload = mask(payload.asBytes(), mask = hash)
        val maskedPayloadWithHash = buildMessage {
            put(hash)
            put(maskedPayload)
        }
        return key.deterministicEncryption(maskedPayloadWithHash)
    }

    fun decrypt(encrypted: Message): Result<Message> = runCatching {
        val decrypted = key.deterministicDecryption(encrypted)
            .getOrElse { return Result.failure(it) }
        val destructor = decrypted.destructor()
        val hash = destructor.getMessage(32) // 32 == the size of the hash
        val maskedPayload = destructor.getRest()
        val payload = mask(maskedPayload.asBytes(), mask = hash.asBytes())
        Message.fromBytes(payload)
    }

    private fun mask(message: ByteArray, mask: ByteArray): ByteArray =
        message.mapIndexed { index, byte -> byte xor mask[index % mask.size] }
            .toByteArray()
}
