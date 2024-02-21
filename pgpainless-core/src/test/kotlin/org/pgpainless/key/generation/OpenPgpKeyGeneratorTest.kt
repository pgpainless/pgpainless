//  SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
//  SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation

import org.bouncycastle.bcpg.sig.PrimaryUserID
import org.bouncycastle.extensions.toAsciiArmor
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVectorGenerator
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.eddsa.EdDSACurve
import org.pgpainless.key.generation.type.rsa.RsaLength
import org.pgpainless.key.generation.type.xdh.XDHSpec
import org.pgpainless.policy.Policy
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets
import org.pgpainless.util.DateUtil

class OpenPgpKeyGeneratorTest {

    @Test
    fun `minimal call with opinionated builder adds a default DK sig but no user info`() {
        val key =
            OpenPgpKeyGenerator.buildV4Key().setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)).build()

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
            OpenPgpKeyGenerator.buildV4Key()
                .unopinionated()
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519))
                .build()

        assertFalse(key.publicKey.keySignatures.hasNext())

        println(key.toAsciiArmor())
    }

    @Test
    fun `adding a direct-key signature with the opinionated builder omits the default DK sig`() {
        val key =
            OpenPgpKeyGenerator.buildV4Key()
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                    addDirectKeySignature() // "overwrites" the default dk sig
                }
                .build()

        assertEquals(1, key.publicKey.keySignatures.asSequence().toList().size)

        println(key.toAsciiArmor())
    }

    @Test
    fun `adding two user-ids will mark the first one as primary`() {
        val key =
            OpenPgpKeyGenerator.buildV4Key()
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                    addUserId("Primary <primary@example.com>")
                    addUserId("Non Primary <non-primary@example.com>")
                }
                .build()

        val info = PGPainless.inspectKeyRing(key)
        assertEquals("Primary <primary@example.com>", info.primaryUserId)
    }

    @Test
    fun `adding two user-ids but mark the first as non-primary will mark the second one as primary`() {
        val key =
            OpenPgpKeyGenerator.buildV4Key()
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                    addUserId(
                        "Non Primary <non-primary@example.com>",
                        SelfSignatureSubpackets.applyHashed {
                            // Not primary
                            setPrimaryUserId(PrimaryUserID(false, false))
                        })
                    addUserId("Primary <primary@example.com>")
                }
                .build()

        val info = PGPainless.inspectKeyRing(key)
        assertEquals("Primary <primary@example.com>", info.primaryUserId)
    }

    @Test
    fun testUnopinionatedV4() {
        // Unopinionated
        OpenPgpKeyGenerator.buildV4Key()
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
        OpenPgpKeyGenerator.buildV4Key(creationTime = time)
            .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519), listOf(KeyFlag.CERTIFY_OTHER)) {
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
        OpenPgpKeyGenerator.buildV4Key()
            .setPrimaryKey(KeyType.RSA(RsaLength._3072), keyFlags = listOf(KeyFlag.CERTIFY_OTHER))
            .build()
            .toAsciiArmor()
            .let { println(it) }
    }

    @Test
    fun `key generation with too weak PK algorithms fails`() {
        val policy = Policy()
        policy.publicKeyAlgorithmPolicy =
            Policy.PublicKeyAlgorithmPolicy(buildMap { put(PublicKeyAlgorithm.RSA_GENERAL, 3072) })

        assertThrows<IllegalArgumentException> {
            OpenPgpKeyGenerator.buildV4Key(policy)
                // opinionated builder verifies PK parameters
                .setPrimaryKey(KeyType.RSA(RsaLength._2048)) // too weak
        }
    }

    @Test
    fun `unopinionated key generation with too weak PK algorithm does not fail`() {
        val policy = Policy()
        policy.publicKeyAlgorithmPolicy =
            Policy.PublicKeyAlgorithmPolicy(buildMap { put(PublicKeyAlgorithm.RSA_GENERAL, 3072) })

        OpenPgpKeyGenerator.buildV4Key(policy)
            .unopinionated() // unopinionated builder allows for non-compliant configurations
            .setPrimaryKey(KeyType.RSA(RsaLength._2048))
    }

    @Test
    fun `skip default DirectKey signature will not add one`() {
        val key =
            OpenPgpKeyGenerator.buildV4Key()
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)) { skipDefaultSignature() }
                .build()

        assertFalse(key.publicKey.keySignatures.hasNext())
    }

    @Test
    fun testModernKeyGeneration() {
        println(KeyRingTemplates().modernKeyRing("null").toAsciiArmor())
    }

    @Test
    fun `opinionated add UserID with weak hash algorithm fails`() {
        val policy = Policy()
        assertThrows<IllegalArgumentException> {
            OpenPgpKeyGenerator.buildV4(policy).setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                addUserId("Alice <alice@example.org>", hashAlgorithm = HashAlgorithm.SHA1)
            }
        }
    }

    @Test
    fun `unopinionated add UserID with weak hash algorithm is okay`() {
        val policy = Policy()
        OpenPgpKeyGenerator.buildV4(policy).unopinionated().setPrimaryKey(
            KeyType.EDDSA(EdDSACurve._Ed25519)) {
                addUserId("Alice <alice@example.org>", hashAlgorithm = HashAlgorithm.SHA1)
            }
    }

    @Test
    fun `opinionated add UserAttribute with weak hash algorithm fails`() {
        val policy = Policy()
        assertThrows<IllegalArgumentException> {
            OpenPgpKeyGenerator.buildV4(policy).setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                addUserAttribute(
                    PGPUserAttributeSubpacketVectorGenerator().generate(),
                    hashAlgorithm = HashAlgorithm.SHA1)
            }
        }
    }

    @Test
    fun `unopinionated add UserAttribute with weak hash algorithm is okay`() {
        val policy = Policy()
        OpenPgpKeyGenerator.buildV4(policy).unopinionated().setPrimaryKey(
            KeyType.EDDSA(EdDSACurve._Ed25519)) {
                addUserAttribute(
                    PGPUserAttributeSubpacketVectorGenerator().generate(),
                    hashAlgorithm = HashAlgorithm.SHA1)
            }
    }

    @Test
    fun `opinionated add DK sig with weak hash algorithm fails`() {
        val policy = Policy()
        assertThrows<IllegalArgumentException> {
            OpenPgpKeyGenerator.buildV4(policy).setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                addDirectKeySignature(hashAlgorithm = HashAlgorithm.SHA1)
            }
        }
    }

    @Test
    fun `unopinionated add DK sig with weak hash algorithm is okay`() {
        val policy = Policy()
        OpenPgpKeyGenerator.buildV4(policy).unopinionated().setPrimaryKey(
            KeyType.EDDSA(EdDSACurve._Ed25519)) {
                addDirectKeySignature(hashAlgorithm = HashAlgorithm.SHA1)
            }
    }

    @Test
    fun `opinionated add UserID with predating binding time fails`() {
        val policy = Policy()
        val t0 = DateUtil.parseUTCDate("2024-01-01 00:00:00 UTC")
        val t1 = DateUtil.parseUTCDate("2024-02-01 00:00:00 UTC")

        assertThrows<IllegalArgumentException> {
            OpenPgpKeyGenerator.buildV4(policy, t1).setPrimaryKey(
                KeyType.EDDSA(EdDSACurve._Ed25519)) {
                    addUserId("Alice <alice@example.org>", bindingTime = t0)
                }
        }
    }

    @Test
    fun `unopinionated add UserID with predating binding time is okay`() {
        val policy = Policy()
        val t0 = DateUtil.parseUTCDate("2024-01-01 00:00:00 UTC")
        val t1 = DateUtil.parseUTCDate("2024-02-01 00:00:00 UTC")

        OpenPgpKeyGenerator.buildV4(policy, t1).unopinionated().setPrimaryKey(
            KeyType.EDDSA(EdDSACurve._Ed25519)) {
                addUserId("Alice <alice@example.org>", bindingTime = t0)
            }
    }

    @Test
    fun `opinionated add UserAttribute with predating binding time fails`() {
        val policy = Policy()
        val t0 = DateUtil.parseUTCDate("2024-01-01 00:00:00 UTC")
        val t1 = DateUtil.parseUTCDate("2024-02-01 00:00:00 UTC")

        assertThrows<IllegalArgumentException> {
            OpenPgpKeyGenerator.buildV4(policy, t1).setPrimaryKey(
                KeyType.EDDSA(EdDSACurve._Ed25519)) {
                    addUserAttribute(
                        PGPUserAttributeSubpacketVectorGenerator().generate(), bindingTime = t0)
                }
        }
    }

    @Test
    fun `unopinionated add UserAttribute with predating binding time is okay`() {
        val policy = Policy()
        val t0 = DateUtil.parseUTCDate("2024-01-01 00:00:00 UTC")
        val t1 = DateUtil.parseUTCDate("2024-02-01 00:00:00 UTC")

        OpenPgpKeyGenerator.buildV4(policy, t1).unopinionated().setPrimaryKey(
            KeyType.EDDSA(EdDSACurve._Ed25519)) {
                addUserAttribute(
                    PGPUserAttributeSubpacketVectorGenerator().generate(), bindingTime = t0)
            }
    }

    @Test
    fun `opinionated add DK sig with predating binding time fails`() {
        val policy = Policy()
        val t0 = DateUtil.parseUTCDate("2024-01-01 00:00:00 UTC")
        val t1 = DateUtil.parseUTCDate("2024-02-01 00:00:00 UTC")

        assertThrows<IllegalArgumentException> {
            OpenPgpKeyGenerator.buildV4(policy, t1).setPrimaryKey(
                KeyType.EDDSA(EdDSACurve._Ed25519)) {
                    addDirectKeySignature(bindingTime = t0)
                }
        }
    }

    @Test
    fun `unopinionated add DK sig with predating binding time is okay`() {
        val policy = Policy()
        val t0 = DateUtil.parseUTCDate("2024-01-01 00:00:00 UTC")
        val t1 = DateUtil.parseUTCDate("2024-02-01 00:00:00 UTC")

        OpenPgpKeyGenerator.buildV4(policy, t1).unopinionated().setPrimaryKey(
            KeyType.EDDSA(EdDSACurve._Ed25519)) {
                addDirectKeySignature(bindingTime = t0)
            }
    }

    @Test
    fun `opinionated add subkey with predating creation time fails`() {
        val policy = Policy()
        val t0 = DateUtil.parseUTCDate("2024-01-01 00:00:00 UTC")
        val t1 = DateUtil.parseUTCDate("2024-02-01 00:00:00 UTC")

        assertThrows<IllegalArgumentException> {
            OpenPgpKeyGenerator.buildV4(policy, t1)
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519))
                .addSubkey(KeyType.XDH(XDHSpec._X25519), t0)
        }
    }

    @Test
    fun `unopinionated add subkey with predating creation time is okay`() {
        val policy = Policy()
        val t0 = DateUtil.parseUTCDate("2024-01-01 00:00:00 UTC")
        val t1 = DateUtil.parseUTCDate("2024-02-01 00:00:00 UTC")

        OpenPgpKeyGenerator.buildV4(policy, t1)
            .unopinionated()
            .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519))
            .addSubkey(KeyType.XDH(XDHSpec._X25519), t0)
    }

    @Test
    fun `opinionated add subkey with predating binding time fails`() {
        val policy = Policy()
        val t0 = DateUtil.parseUTCDate("2024-01-01 00:00:00 UTC")
        val t1 = DateUtil.parseUTCDate("2024-02-01 00:00:00 UTC")

        assertThrows<IllegalArgumentException> {
            OpenPgpKeyGenerator.buildV4(policy, t1)
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519))
                .addSubkey(KeyType.XDH(XDHSpec._X25519)) { addBindingSignature(bindingTime = t0) }
        }
    }

    @Test
    fun `unopinionated add subkey with predating binding time is okay`() {
        val policy = Policy()
        val t0 = DateUtil.parseUTCDate("2024-01-01 00:00:00 UTC")
        val t1 = DateUtil.parseUTCDate("2024-02-01 00:00:00 UTC")

        OpenPgpKeyGenerator.buildV4(policy, t1)
            .unopinionated()
            .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519))
            .addSubkey(KeyType.XDH(XDHSpec._X25519)) { addBindingSignature(bindingTime = t0) }
    }
}
