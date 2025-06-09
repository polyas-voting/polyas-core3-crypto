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

import de.polyas.core3.crypto.elgamal.ElGamalEncoding.blockSize
import de.polyas.core3.crypto.elgamal.ElGamalEncoding.decodeToMessage
import de.polyas.core3.crypto.elgamal.ElGamalEncoding.decodeToString
import de.polyas.core3.crypto.elgamal.ElGamalEncoding.encodeBytes
import de.polyas.core3.crypto.elgamal.ElGamalEncoding.encodeString
import de.polyas.core3.crypto.elgamal.instance.SchnorrGroup
import de.polyas.core3.crypto.elgamal.instance.EllipticCurveInst
import de.polyas.core3.crypto.std.Message.Companion.fromHexString
import java.math.BigInteger
import kotlin.math.floor
import kotlin.math.ln
import kotlin.test.Test
import kotlin.test.assertEquals

class ElGamalEncodingTest {
    @Test
    fun testString() {
        testString(EllipticCurveInst())
        testString(SchnorrGroup.group512)
    }

    @Test
    fun testHex() {
        testHex(EllipticCurveInst())
        testHex(SchnorrGroup.group512)
    }

    @Test
    fun testHex1() {
        testHex1(EllipticCurveInst())
        testHex1(SchnorrGroup.group512)
    }

    @Test
    fun testHex2() {
        testHex2(EllipticCurveInst())
        testHex2(SchnorrGroup.group512)
    }

    @Test
    fun testHex3() {
        testHex3(EllipticCurveInst())
        testHex3(SchnorrGroup.group512)
    }

    private fun testString(group: CyclicGroup<*>) {
        val str =
            "ablaksdjfasdfaisuhfaisldfahlwiuehrlwiauhflaskjdfhlaskjdfhwaiuehfliasuhdflkajshdflkajshdflkasjdhflaksjdhflaksjdfhlaksjdfhlas"
        for (i in 1 until str.length) {
            val s = str.substring(0, i)
            testString(group, s)
        }
    }

    private fun testString(group: CyclicGroup<*>, str: String) {
        val x = encodeString(str, group)
        val res = decodeToString(x, group).getOrThrow()
        assertEquals(str, res)
    }

    private fun testHex(group: CyclicGroup<*>) {
        val hex = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000FE00"
        val message = fromHexString(hex)
        val x = encodeBytes(message.asBytes(), group)
        val y = decodeToMessage(x, group).getOrThrow()
        assertEquals(message, y)
    }

    private fun testHex1(group: CyclicGroup<*>) {
        val hex =
            "00000000000000000000000000000000030000000000000000000000000000000000000000000000000000020000000000000000000000000000000001"
        val message = fromHexString(hex)
        val x = encodeBytes(message.asBytes(), group)
        val y = decodeToMessage(x, group).getOrThrow()
        assertEquals(message, y)
    }

    private fun testHex2(group: CyclicGroup<*>) {
        val hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        val message = fromHexString(hex)
        val x = encodeBytes(message.asBytes(), group)
        val y = decodeToMessage(x, group).getOrThrow()
        assertEquals(message, y)
    }

    private fun testHex3(group: CyclicGroup<*>) {
        val hex = "F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0"
        val message = fromHexString(hex)
        val x = encodeBytes(message.asBytes(), group)
        val y = decodeToMessage(x, group).getOrThrow()
        assertEquals(message, y)
    }

    @Test
    fun testBlockSize() {
        for (n in 256 * 256 * 256 - 5 until 256 * 256 * 256 + 5) {
            val bi: BigInteger = BigInteger.valueOf(n.toLong())
            val x = blockSize(bi)
            val y = floor(ln(n.toDouble()) / ln(2.0)).toInt() / 8
            val z = floor(ln(n.toDouble()) / ln(2.0) / 8.0).toInt()
            assertEquals(x.toLong(), y.toLong())
            assertEquals(x.toLong(), z.toLong())
        }
    }

    @Test
    fun testLongMessagesStandardGroup() {
        val group = SchnorrGroup.group512
        testLongMessages(group, 2050)
    }

    @Test
    fun testLongMessagesEC() {
        val group = EllipticCurveInst()
        testLongMessages(group, 600)
    }

    private fun testLongMessages(group: CyclicGroup<*>, N: Int) {
        for (i in 1 until N) {
            val msg = "x".repeat(i)
            testMessageEncodeDecode(group, msg)
        }
    }

    private fun <E> testMessageEncodeDecode(group: CyclicGroup<E>, msg: String) {
        val codes = encodeString(msg, group)
        val decode: String = decodeToString(codes, group).getOrThrow()
        assertEquals(msg, decode)

        for (code in codes) {
            val e = group.encode(code)
            val code1 = group.decode(e)
            assertEquals(code, code1)
        }
    }
}
