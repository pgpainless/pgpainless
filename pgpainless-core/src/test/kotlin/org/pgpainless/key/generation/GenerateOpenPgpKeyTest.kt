// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation

import java.io.InputStream
import org.bouncycastle.util.io.Streams
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.opentest4j.TestAbortedException
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.eddsa.EdDSACurve
import org.pgpainless.key.generation.type.rsa.RsaLength
import org.pgpainless.key.generation.type.xdh.XDHSpec
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.policy.Policy
import org.pgpainless.util.DateUtil

class GenerateOpenPgpKeyTest {

    @Test
    fun test() {
        val date = DateUtil.parseUTCDate("2020-04-01 10:00:00 UTC")
        val key =
            GenerateOpenPgpKey(Policy.getInstance(), date)
                .buildV4Key(KeyType.EDDSA(EdDSACurve._Ed25519), listOf(KeyFlag.CERTIFY_OTHER))
                .addUserId("Alice")
                .addEncryptionSubkey(KeyType.XDH(XDHSpec._X25519))
                .addSigningSubkey(KeyType.EDDSA(EdDSACurve._Ed25519))
                .build(SecretKeyRingProtector.unprotectedKeys())
        println(PGPainless.asciiArmor(key))
    }

    @Test
    fun minimal() {
        val key =
            GenerateOpenPgpKey(Policy.getInstance())
                .buildV4Key(KeyType.EDDSA(EdDSACurve._Ed25519), listOf(KeyFlag.CERTIFY_OTHER))
                .build()
        println(PGPainless.asciiArmor(key))
    }

    @Test
    fun minimalWithUserId() {
        val key =
            GenerateOpenPgpKey(Policy.getInstance())
                .buildV4Key(KeyType.EDDSA(EdDSACurve._Ed25519), listOf(KeyFlag.CERTIFY_OTHER))
                .addUserId("Alice <alice@pgpainless.org>")
                .build()
        println(PGPainless.asciiArmor(key))
    }

    @Test
    fun primaryKeyMustBeCertificationCapable() {
        assertThrows<IllegalArgumentException> {
            GenerateOpenPgpKey(Policy.getInstance())
                // XDH is not signing/certification capable
                .buildV4Key(KeyType.XDH(XDHSpec._X25519))
        }
    }

    @Test
    fun encryptionSubkeyMustBeEncryptionCapable() {
        val builder =
            GenerateOpenPgpKey(Policy.getInstance()).buildV4Key(KeyType.EDDSA(EdDSACurve._Ed25519))

        assertThrows<IllegalArgumentException> {
            builder.addEncryptionSubkey(KeyType.EDDSA(EdDSACurve._Ed25519))
        }
    }

    @Test
    fun signingSubkeysMustBeSigningCapable() {
        val builder =
            GenerateOpenPgpKey(Policy.getInstance()).buildV4Key(KeyType.EDDSA(EdDSACurve._Ed25519))

        assertThrows<IllegalArgumentException> {
            builder.addSigningSubkey(KeyType.XDH(XDHSpec._X25519))
        }
    }

    @Test
    fun testKeyGenerationWithUnacceptablePKAlgorithmFails() {
        // Policy only allows RSA 4096 algorithms
        val policy =
            Policy(
                publicKeyAlgorithmPolicy =
                    Policy.PublicKeyAlgorithmPolicy(mapOf(PublicKeyAlgorithm.RSA_GENERAL to 4096)),
            )
        val builder = GenerateOpenPgpKey(policy)

        assertThrows<IllegalArgumentException> {
            builder.buildV4Key(KeyType.RSA(RsaLength._3072)) // too weak
        }

        val v4Builder = builder.buildV4Key(KeyType.RSA(RsaLength._4096)) // ok
        assertThrows<IllegalArgumentException> {
            v4Builder.addSigningSubkey(KeyType.RSA(RsaLength._2048)) // too weak
        }
    }

    @Test
    fun testKeyGenerationWithJPEGAttribute() {
        val key =
            GenerateOpenPgpKey(Policy.getInstance())
                .buildV4Key(KeyType.EDDSA(EdDSACurve._Ed25519))
                .addJpegImage(requireResource("suzanne.jpg"))
                .build()

        assertTrue(key.publicKey.userAttributes.hasNext())
        assertArrayEquals(
            Streams.readAll(requireResource("suzanne.jpg")),
            key.publicKey.userAttributes.next().imageAttribute.imageData)
    }

    private fun requireResource(resourceName: String): InputStream {
        return javaClass.classLoader.getResourceAsStream(resourceName)
            ?: throw TestAbortedException(
                "Cannot read resource $resourceName: InputStream is null.")
    }

    fun testAround() {
        GenerateOpenPgpKey(Policy.getInstance())
            .buildKeyV4()
            .primaryKey(RSA, listOf(KeyFlag.CERTIFY_OTHER))

        GenerateOpenPgpKey(Policy.getInstance())
            .buildKey()
            .unopinionated()
            .apply {
                primaryKey(RSA, creationTime)
                    .directKeySignature(callback)
            }

    }

    interface TestInterface<T : TestInterface<T>> {
        fun doSomething(): T
    }

    class LowerTestClass : TestInterface<LowerTestClass> {
        override fun doSomething(): LowerTestClass {
            TODO("Not yet implemented")
        }

    }

    class TestClass : TestInterface<TestClass> {

        override fun doSomething(): TestClass {
            TODO("Not yet implemented")
        }

        fun lower(): LowerTestClass {
            return LowerTestClass()
        }

    }
}
