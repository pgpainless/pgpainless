//  SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
//  SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation

import java.time.Duration
import java.time.temporal.ChronoUnit
import org.bouncycastle.bcpg.attr.ImageAttribute
import org.bouncycastle.bcpg.sig.PrimaryUserID
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVectorGenerator
import org.bouncycastle.util.encoders.Hex
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.algorithm.PublicKeyAlgorithm
import org.pgpainless.bouncycastle.extensions.directKeySignatures
import org.pgpainless.bouncycastle.extensions.subkeyBindingSignatures
import org.pgpainless.bouncycastle.extensions.toAsciiArmor
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.eddsa.EdDSACurve
import org.pgpainless.key.generation.type.rsa.RsaLength
import org.pgpainless.key.generation.type.xdh.XDHSpec
import org.pgpainless.policy.Policy
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil
import org.pgpainless.util.DateUtil

class OpenPgpKeyGeneratorTest {

    @Test
    fun `minimal call with opinionated builder adds a default DK sig but no user info`() {
        val key =
            PGPainless.generateOpenPgpKey()
                .buildV4Key()
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519))
                .build()

        assertFalse(key.publicKey.userIDs.hasNext(), "Key MUST NOT have a UserID")
        assertFalse(key.publicKey.userAttributes.hasNext(), "Key MUST NOT have a UserAttribute")
        assertEquals(
            1,
            key.publicKey.directKeySignatures.count(),
            "Opinionated builder adds exactly one DirectKey signature")

        println(key.toAsciiArmor())
    }

    @Test
    fun `minimal call with unopinionated builder does not add a default DK sig`() {
        val key =
            PGPainless.generateOpenPgpKey()
                .buildV4Key()
                .unopinionated()
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519))
                .build()

        assertTrue(key.publicKey.directKeySignatures.none())

        println(key.toAsciiArmor())
    }

    @Test
    fun `adding a direct-key signature with the opinionated builder omits the default DK sig`() {
        val key =
            PGPainless.generateOpenPgpKey()
                .buildV4Key()
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                    addDirectKeySignature() // "overwrites" the default dk sig
                }
                .build()

        assertEquals(1, key.publicKey.directKeySignatures.count())

        println(key.toAsciiArmor())
    }

    @Test
    fun `adding two user-ids will mark the first one as primary`() {
        val key =
            PGPainless.generateOpenPgpKey()
                .buildV4Key()
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
            PGPainless.generateOpenPgpKey()
                .buildV4Key()
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
    fun `adding two user-attributes will mark the first one as primary`() {
        val policy = Policy()

        val attr1 =
            PGPUserAttributeSubpacketVectorGenerator()
                .apply { setImageAttribute(ImageAttribute.JPEG, byteArrayOf(0x01b)) }
                .generate()
        val attr2 =
            PGPUserAttributeSubpacketVectorGenerator()
                .apply { setImageAttribute(ImageAttribute.JPEG, byteArrayOf(0x02b)) }
                .generate()

        val key =
            PGPainless.generateOpenPgpKey(policy)
                .buildV4Key()
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                    addUserAttribute(attr1) // primary, since it is the first
                    addUserAttribute(attr2) // non-primary
                }
                .build()

        assertTrue(
            key.publicKey
                .getSignaturesForUserAttribute(attr1)
                .asSequence()
                .single()
                .hashedSubPackets
                .isPrimaryUserID)
        assertFalse(
            key.publicKey
                .getSignaturesForUserAttribute(attr2)
                .asSequence()
                .single()
                .hashedSubPackets
                .isPrimaryUserID)
    }

    @Test
    fun `adding single user-id and single user-attribute will mark both as primary`() {
        val policy = Policy()

        val userId = "Alice <alice@pgpainless.org>"
        val userAttribute =
            PGPUserAttributeSubpacketVectorGenerator()
                .apply { setImageAttribute(ImageAttribute.JPEG, byteArrayOf(0x01b)) }
                .generate()

        val key =
            PGPainless.generateOpenPgpKey(policy)
                .buildV4Key()
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                    addUserId(userId)
                    addUserAttribute(userAttribute)
                }
                .build()

        assertTrue(
            key.publicKey
                .getSignaturesForUserAttribute(userAttribute)
                .asSequence()
                .single()
                .hashedSubPackets
                .isPrimaryUserID)
        assertTrue(
            key.publicKey
                .getSignaturesForID(userId)
                .asSequence()
                .single()
                .hashedSubPackets
                .isPrimaryUserID)
    }

    @Test
    fun `adding signing key will add embedded back-signature`() {
        val key =
            PGPainless.generateOpenPgpKey()
                .buildV4Key()
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519))
                .addSubkey(KeyType.EDDSA(EdDSACurve._Ed25519), listOf(KeyFlag.SIGN_DATA))
                .build()

        assertFalse(
            key.publicKeys
                .asSequence()
                .last()
                .subkeyBindingSignatures
                .single()
                .hashedSubPackets
                .embeddedSignatures
                .isEmpty)
    }

    @Test
    fun testUnopinionatedV4() {
        // Unopinionated
        PGPainless.generateOpenPgpKey()
            .buildV4Key()
            .unopinionated()
            .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                addDirectKeySignature()
                addUserId("Alice <alice@pgpainless.org>")
            }
            .addSubkey(KeyType.EDDSA(EdDSACurve._Ed25519)) { addBindingSignature() }
            .addSubkey(KeyType.XDH(XDHSpec._X25519)) { addBindingSignature() }
            .build()
            .let { println(it.toAsciiArmor()) }
    }

    @Test
    fun testOpinionatedV4() {
        // Opinionated
        val time = DateUtil.parseUTCDate("2024-01-01 00:00:00 UTC")
        PGPainless.generateOpenPgpKey()
            .buildV4Key(creationTime = time)
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
        PGPainless.generateOpenPgpKey()
            .buildV4Key()
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
            PGPainless.generateOpenPgpKey(policy)
                .buildV4Key()
                // opinionated builder verifies PK parameters
                .setPrimaryKey(KeyType.RSA(RsaLength._2048)) // too weak
        }
    }

    @Test
    fun `unopinionated key generation with too weak PK algorithm does not fail`() {
        val policy = Policy()
        policy.publicKeyAlgorithmPolicy =
            Policy.PublicKeyAlgorithmPolicy(buildMap { put(PublicKeyAlgorithm.RSA_GENERAL, 3072) })

        PGPainless.generateOpenPgpKey(policy)
            .buildV4Key()
            .unopinionated() // unopinionated builder allows for non-compliant configurations
            .setPrimaryKey(KeyType.RSA(RsaLength._2048))
    }

    @Test
    fun `skip default DirectKey signature will not add one`() {
        val key =
            PGPainless.generateOpenPgpKey()
                .buildV4Key()
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)) { skipDefaultSignature() }
                .build()

        assertTrue(key.publicKey.directKeySignatures.none())
    }

    @Test
    fun testModernKeyGeneration() {
        println(KeyRingTemplates().modernKeyRing("null").toAsciiArmor())
    }

    @Test
    fun `opinionated add UserID with weak hash algorithm fails`() {
        val policy = Policy()
        assertThrows<IllegalArgumentException> {
            PGPainless.generateOpenPgpKey(policy).buildV4Key().setPrimaryKey(
                KeyType.EDDSA(EdDSACurve._Ed25519)) {
                    addUserId("Alice <alice@example.org>", hashAlgorithm = HashAlgorithm.SHA1)
                }
        }
    }

    @Test
    fun `unopinionated add UserID with weak hash algorithm is okay`() {
        val policy = Policy()
        PGPainless.generateOpenPgpKey(policy).buildV4Key().unopinionated().setPrimaryKey(
            KeyType.EDDSA(EdDSACurve._Ed25519)) {
                addUserId("Alice <alice@example.org>", hashAlgorithm = HashAlgorithm.SHA1)
            }
    }

    @Test
    fun `opinionated add UserAttribute with weak hash algorithm fails`() {
        val policy = Policy()
        assertThrows<IllegalArgumentException> {
            PGPainless.generateOpenPgpKey(policy).buildV4Key().setPrimaryKey(
                KeyType.EDDSA(EdDSACurve._Ed25519)) {
                    addUserAttribute(
                        PGPUserAttributeSubpacketVectorGenerator().generate(),
                        hashAlgorithm = HashAlgorithm.SHA1)
                }
        }
    }

    @Test
    fun `unopinionated add UserAttribute with weak hash algorithm is okay`() {
        val policy = Policy()
        PGPainless.generateOpenPgpKey(policy).buildV4Key().unopinionated().setPrimaryKey(
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
            PGPainless.generateOpenPgpKey(policy).buildV4Key().setPrimaryKey(
                KeyType.EDDSA(EdDSACurve._Ed25519)) {
                    addDirectKeySignature(hashAlgorithm = HashAlgorithm.SHA1)
                }
        }
    }

    @Test
    fun `unopinionated add DK sig with weak hash algorithm is okay`() {
        val policy = Policy()
        PGPainless.generateOpenPgpKey(policy).buildV4Key().unopinionated().setPrimaryKey(
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
            PGPainless.generateOpenPgpKey(policy).buildV4Key(t1).setPrimaryKey(
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

        PGPainless.generateOpenPgpKey(policy).buildV4Key(t1).unopinionated().setPrimaryKey(
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
            PGPainless.generateOpenPgpKey(policy).buildV4Key(t1).setPrimaryKey(
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

        PGPainless.generateOpenPgpKey(policy).buildV4Key(t1).unopinionated().setPrimaryKey(
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
            PGPainless.generateOpenPgpKey(policy).buildV4Key(t1).setPrimaryKey(
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

        PGPainless.generateOpenPgpKey(policy).buildV4Key(t1).unopinionated().setPrimaryKey(
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
            PGPainless.generateOpenPgpKey(policy)
                .buildV4Key(t1)
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519))
                .addSubkey(KeyType.XDH(XDHSpec._X25519), null, t0)
        }
    }

    @Test
    fun `unopinionated add subkey with predating creation time is okay`() {
        val policy = Policy()
        val t0 = DateUtil.parseUTCDate("2024-01-01 00:00:00 UTC")
        val t1 = DateUtil.parseUTCDate("2024-02-01 00:00:00 UTC")

        PGPainless.generateOpenPgpKey(policy)
            .buildV4Key(t1)
            .unopinionated()
            .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519))
            .addSubkey(KeyType.XDH(XDHSpec._X25519), null, t0)
    }

    @Test
    fun `opinionated add subkey with predating binding time fails`() {
        val policy = Policy()
        val t0 = DateUtil.parseUTCDate("2024-01-01 00:00:00 UTC")
        val t1 = DateUtil.parseUTCDate("2024-02-01 00:00:00 UTC")

        assertThrows<IllegalArgumentException> {
            PGPainless.generateOpenPgpKey(policy)
                .buildV4Key(t1)
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519))
                .addSubkey(KeyType.XDH(XDHSpec._X25519)) { addBindingSignature(bindingTime = t0) }
        }
    }

    @Test
    fun `unopinionated add subkey with predating binding time is okay`() {
        val policy = Policy()
        val t0 = DateUtil.parseUTCDate("2024-01-01 00:00:00 UTC")
        val t1 = DateUtil.parseUTCDate("2024-02-01 00:00:00 UTC")

        PGPainless.generateOpenPgpKey(policy)
            .buildV4Key(t1)
            .unopinionated()
            .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519))
            .addSubkey(KeyType.XDH(XDHSpec._X25519)) { addBindingSignature(bindingTime = t0) }
    }

    @Test
    fun `opinionated add subkey with weak binding signature hash algorithm fails`() {
        val policy = Policy()

        assertThrows<IllegalArgumentException> {
            PGPainless.generateOpenPgpKey(policy)
                .buildV4Key()
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519))
                .addSubkey(KeyType.XDH(XDHSpec._X25519)) {
                    addBindingSignature(hashAlgorithm = HashAlgorithm.SHA1)
                }
        }
    }

    @Test
    fun `unopinionated add subkey with weak binding signature hash algorithm is okay`() {
        val policy = Policy()

        PGPainless.generateOpenPgpKey(policy)
            .buildV4Key()
            .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519))
            .unopinionated()
            .addSubkey(KeyType.XDH(XDHSpec._X25519)) {
                addBindingSignature(hashAlgorithm = HashAlgorithm.SHA1)
            }
    }

    @Test
    fun `opinionated set primary key to encryption key fails`() {
        val policy = Policy()

        assertThrows<IllegalArgumentException> {
            PGPainless.generateOpenPgpKey(policy)
                .buildV4Key()
                .setPrimaryKey(KeyType.XDH(XDHSpec._X25519))
        }
    }

    @Test
    fun `opinionated set primary key to sign-only algorithm but with encryption flag fails`() {
        val policy = Policy()

        assertThrows<IllegalArgumentException> {
            PGPainless.generateOpenPgpKey(policy)
                .buildV4Key()
                .setPrimaryKey(
                    KeyType.EDDSA(EdDSACurve._Ed25519),
                    listOf(KeyFlag.CERTIFY_OTHER, KeyFlag.ENCRYPT_STORAGE))
        }
    }

    @Test
    fun `unopinionated set primary key to sign-only algorithm but with encryption flag is okay`() {
        val policy = Policy()

        PGPainless.generateOpenPgpKey(policy)
            .buildV4Key()
            .unopinionated()
            .setPrimaryKey(
                KeyType.EDDSA(EdDSACurve._Ed25519),
                listOf(KeyFlag.CERTIFY_OTHER, KeyFlag.ENCRYPT_STORAGE))
    }

    @Test
    fun `opinionated set primary key without any key flags is okay`() {
        val policy = Policy()

        val key =
            PGPainless.generateOpenPgpKey(policy)
                .buildV4Key()
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519), keyFlags = null)
                .build()

        assertNull(SignatureSubpacketsUtil.getKeyFlags(key.publicKey.signatures.next()))
    }

    @Test
    fun `opinionated add encryption-only subkey with additional sign flag fails`() {
        val policy = Policy()

        assertThrows<IllegalArgumentException> {
            PGPainless.generateOpenPgpKey(policy)
                .buildV4Key()
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519))
                .addSubkey(
                    KeyType.XDH(XDHSpec._X25519), listOf(KeyFlag.ENCRYPT_COMMS, KeyFlag.SIGN_DATA))
        }
    }

    @Test
    fun `opinionated add sign-only sukey but with additional encryption flag fails`() {
        val policy = Policy()

        assertThrows<IllegalArgumentException> {
            PGPainless.generateOpenPgpKey(policy)
                .buildV4Key()
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519))
                .addSubkey(
                    KeyType.EDDSA(EdDSACurve._Ed25519),
                    listOf(KeyFlag.SIGN_DATA, KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE))
        }
    }

    @Test
    fun `unopinionated add sign-only sukey but with additional encryption flag is okay`() {
        val policy = Policy()

        PGPainless.generateOpenPgpKey(policy)
            .buildV4Key()
            .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519))
            .unopinionated()
            .addSubkey(
                KeyType.EDDSA(EdDSACurve._Ed25519),
                listOf(KeyFlag.SIGN_DATA, KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE))
            .build()
    }

    @Test
    fun `add image attribute to key`() {
        // smallest JPEG according to https://stackoverflow.com/a/2349470/11150851
        val jpegBytes =
            Hex.decode(
                "ffd8ffe000104a46494600010101004800480000ffdb004300030202020202030202020303030304060404040404080606050609080a0a090809090a0c0f0c0a0b0e0b09090d110d0e0f101011100a0c12131210130f101010ffc9000b080001000101011100ffcc000600101005ffda0008010100003f00d2cf20ffd9")

        val key =
            PGPainless.generateOpenPgpKey()
                .buildV4Key()
                .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                    addImageAttribute(jpegBytes.inputStream())
                }
                .build()

        assertArrayEquals(jpegBytes, key.publicKey.userAttributes.next().imageAttribute.imageData)
    }

    @Test
    fun `generate key with expiration time`() {
        val policy = Policy()

        PGPainless.generateOpenPgpKey(policy)
            .buildV4Key()
            .setPrimaryKey(KeyType.EDDSA(EdDSACurve._Ed25519)) {
                addDirectKeySignature(
                    SelfSignatureSubpackets.applyHashed {
                        setKeyExpirationTime(true, Duration.of(5 * 365, ChronoUnit.DAYS))
                    })
                addUserId("Bob")
            }
            .addEncryptionSubkey(KeyType.XDH(XDHSpec._X25519))
            .build()
            .let { println(it.toAsciiArmor()) }
    }
}
