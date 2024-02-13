package org.pgpainless.key.generation

import org.bouncycastle.extensions.toAsciiArmor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.eddsa.EdDSACurve
import org.pgpainless.key.generation.type.rsa.RsaLength
import org.pgpainless.key.generation.type.xdh.XDHSpec
import org.pgpainless.policy.Policy
import org.pgpainless.util.DateUtil

class OpenPgpKeyGeneratorTest {

    @Test
    fun `minimal call with opinionated builder adds a default DK sig but no user info`() {
        val key = buildV4().setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)).build()

        assertFalse(key.publicKey.userIDs.hasNext(), "Key MUST NOT have a UserID")
        assertFalse(key.publicKey.userAttributes.hasNext(), "Key MUST NOT have a UserAttribute")
        assertEquals(
            1,
            key.publicKey.keySignatures.asSequence().toList().size,
            "Opinionated builder adds exactly one DirectKey signature")

        println(key.toAsciiArmor())
    }

    @Test
    fun `minimal call with unopinionated builder does not add a default DK sig`() {
        val key =
            buildV4().unopinionated().setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)).build()

        assertFalse(key.publicKey.keySignatures.hasNext())

        println(key.toAsciiArmor())
    }

    @Test
    fun `adding a direct-key signature with the opinionated builder omits the default DK sig`() {
        val key =
            buildV4()
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                    addDirectKeySignature() // "overwrites" the default dk sig
                }
                .build()

        assertEquals(1, key.publicKey.keySignatures.asSequence().toList().size)

        println(key.toAsciiArmor())
    }

    @Test
    fun testUnopinionatedV4() {
        // Unopinionated
        buildV4()
            .unopinionated()
            .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                addDirectKeySignature()
                addUserId("Alice <alice@pgpainless.org>")
            }
            .addSubkey(KeyType.EDDSA(EdDSACurve._Ed25519)) { addBindingSignature() }
            .addSubkey(KeyType.XDH(XDHSpec._X25519)) { addBindingSignature() }
            .build()
    }

    @Test
    fun testOpinionatedV4() {
        // Opinionated
        val time = DateUtil.parseUTCDate("2024-01-01 00:00:00 UTC")
        buildV4(creationTime = time)
            .setCertificationKey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                addUserId("Alice <alice@pgpainless.org>")
            }
            .addSigningSubkey(KeyType.EDDSA(EdDSACurve._Ed25519))
            .addEncryptionSubkey(KeyType.XDH(XDHSpec._X25519))
            .build()
            .let { println(it.toAsciiArmor()) }
    }

    @Test
    fun testV4Ed25519Curve25519Template() {
        OpenPgpKeyTemplates.v4()
            .ed25519Curve25519("Alice <alice@example.org>", "Alice <alice@pgpainless.org>")
            .let { println(it.toAsciiArmor()) }
    }

    @Test
    fun testV4ComposedRsaTemplate() {
        OpenPgpKeyTemplates.v4()
            .composedRsa("Alice <alice@example.org>", "Alice <alice@pgpainless.org>")
            .let { println(it.toAsciiArmor()) }
    }

    @Test
    fun testV4SingleRsaTemplate() {
        OpenPgpKeyTemplates.v4()
            .singleRsa("Alice <alice@pgpainless.org>", length = RsaLength._3072)
            .let { println(it.toAsciiArmor()) }
    }

    @Test
    fun test() {
        buildV4().setCertificationKey(KeyType.RSA(RsaLength._3072)).build().toAsciiArmor().let {
            println(it)
        }
    }

    @Test
    fun `key generation with too weak PK algorithms fails`() {
        val policy = Policy()
        policy.publicKeyAlgorithmPolicy =
            Policy.PublicKeyAlgorithmPolicy(buildMap { put(PublicKeyAlgorithm.RSA_GENERAL, 3072) })

        assertThrows<IllegalArgumentException> {
            buildV4(policy)
                // opinionated builder verifies PK parameters
                .setPrimaryKey(KeyType.RSA(RsaLength._2048)) // too weak
        }
    }

    @Test
    fun `unopionionated key generation with too weak PK algorithm does not fail`() {
        val policy = Policy()
        policy.publicKeyAlgorithmPolicy =
            Policy.PublicKeyAlgorithmPolicy(buildMap { put(PublicKeyAlgorithm.RSA_GENERAL, 3072) })

        buildV4(policy)
            .unopinionated() // unopinionated builder allows for non-compliant configurations
            .setPrimaryKey(KeyType.RSA(RsaLength._2048))
    }
}
