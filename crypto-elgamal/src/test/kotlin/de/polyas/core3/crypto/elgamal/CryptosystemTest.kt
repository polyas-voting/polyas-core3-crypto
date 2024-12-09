package de.polyas.core3.crypto.elgamal

import de.polyas.core3.crypto.elgamal.instance.SchnorrGroup
import de.polyas.core3.crypto.elgamal.instance.EllipticCurveInst
import de.polyas.core3.crypto.std.SRNG
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class CryptosystemTest {

    class Ctx<G>(val group: CyclicGroup<G>) {
        val cs: Cryptosystem<G> = Cryptosystem(group)
        val sk: BigInteger = group.order.divide(BigInteger.TEN).add(BigInteger.ONE)
        val pk: G = group.powerOfG(sk)
    }

    @Test
    fun encrypt() {
        testEncrypt(Ctx(SchnorrGroup.group512))
        testEncrypt(Ctx(EllipticCurveInst()))
    }

    private fun <G> testEncrypt(ctx: Ctx<G>) {
        val plaintext = SRNG.nextBigInt(ctx.group.messageUpperBound())
        val encrypted = ctx.cs.encrypt(ctx.pk, plaintext)
        val decrypted = ctx.cs.decrypt(ctx.sk, encrypted)
        assertEquals(plaintext, decrypted)
    }

    @Test
    fun encryptRaw() {
        testEncryptRaw(Ctx(SchnorrGroup.group512))
        testEncryptRaw(Ctx(EllipticCurveInst()))
    }

    private fun <G> testEncryptRaw(ctx: Ctx<G>) {
        val e = ctx.group.elementsFromSeed(1, "abc9876")[0]
        val encrypted = ctx.cs.encryptGroupElement(ctx.pk, e)
        val decrypted = ctx.cs.decryptWithoutDecoding(ctx.sk, encrypted)
        assertEquals(e, decrypted)
    }

    @Test
    fun rerandomize() {
        testRerandomize(Ctx(SchnorrGroup.group512))
        testRerandomize(Ctx(EllipticCurveInst()))
    }

    private fun <G> testRerandomize(ctx: Ctx<G>) {
        val e = ctx.group.elementsFromSeed(1, "abc9876")[0]
        val encrypted = ctx.cs.encryptGroupElement(ctx.pk, e)
        val reEncryptionCoin = SRNG.nextBigInt(ctx.group.order)

        // re-encryption with zero re-encryption coin
        val reEncrypted0 = ctx.cs.reRandomize(encrypted, ctx.pk, BigInteger.ZERO)
        assertEquals(encrypted.x, reEncrypted0.x)
        assertEquals(encrypted.y, reEncrypted0.y)
        val decrypted0 = ctx.cs.decryptWithoutDecoding(ctx.sk, reEncrypted0)
        assertEquals(e, decrypted0)

        // re-encryption with random re-encryption coin
        val reEncrypted = ctx.cs.reRandomize(encrypted, ctx.pk, reEncryptionCoin)
        assertNotEquals(encrypted.x, reEncrypted.x)
        assertNotEquals(encrypted.y, reEncrypted.y)
        val decrypted = ctx.cs.decryptWithoutDecoding(ctx.sk, reEncrypted)
        assertEquals(e, decrypted)
    }
}