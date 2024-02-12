package org.pgpainless.key.generation

import openpgp.plusSeconds
import org.bouncycastle.extensions.toAsciiArmor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.pgpainless.algorithm.CertificationType
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.eddsa.EdDSACurve
import org.pgpainless.key.generation.type.xdh.XDHSpec
import org.pgpainless.util.DateUtil

class OpenPgpKeyGeneratorTest {

    @Test
    fun `minimal call with opinionated builder adds a default DK sig but no user info`() {
        val key = buildV4()
            .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519))
            .build()

        assertFalse(key.publicKey.userIDs.hasNext(),
            "Key MUST NOT have a UserID")
        assertFalse(key.publicKey.userAttributes.hasNext(),
            "Key MUST NOT have a UserAttribute")
        assertEquals(1, key.publicKey.keySignatures.asSequence().toList().size,
            "Opinionated builder adds exactly one DirectKey signature")

        println(key.toAsciiArmor())
    }

    @Test
    fun `minimal call with unopinionated builder does not add a default DK sig`() {
        val key = buildV4()
            .unopinionated()
            .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519))
            .build()

        assertFalse(key.publicKey.keySignatures.hasNext())

        println(key.toAsciiArmor())
    }

    @Test
    fun `adding a direct-key signature with the opinionated builder omits the default DK sig`() {
        val key = buildV4()
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
            .addSubkey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                addBindingSignature()
            }
            .addSubkey(KeyType.XDH(XDHSpec._X25519)) {
                addBindingSignature()
            }
            .build()
    }

    @Test
    fun testOpinionatedV4() {
        // Opinionated
        val time = DateUtil.parseUTCDate("2024-01-01 00:00:00 UTC")
        buildV4(creationTime = time)
            .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                addDirectKeySignature()
                addUserId("Alice",
                    bindingTime = time.plusSeconds(60L)!!,
                    hashAlgorithm = HashAlgorithm.SHA384,
                    certificationType = CertificationType.GENERIC)
            }
            .addSubkey(KeyType.XDH(XDHSpec._X25519)) {
                addBindingSignature()
            }
            .build().let { println(it.toAsciiArmor()) }
    }

    @Test
    fun testV4Ed25519Curve25519Template() {
        Templates.V4.ed25519Curve25519("Alice <alice@example.org>", "Alice <alice@pgpainless.org>")
            .let {
                println(it.toAsciiArmor())
            }
    }

}
