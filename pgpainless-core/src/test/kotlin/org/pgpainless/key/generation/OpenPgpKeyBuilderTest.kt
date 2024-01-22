package org.pgpainless.key.generation

import org.bouncycastle.bcpg.attr.ImageAttribute
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVectorGenerator
import org.junit.jupiter.api.Test
import org.pgpainless.PGPainless
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.eddsa.EdDSACurve
import org.pgpainless.key.generation.type.xdh.XDHSpec
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.policy.Policy
import org.pgpainless.util.DateUtil

class OpenPgpKeyBuilderTest {

    @Test
    fun test() {
        val date = DateUtil.parseUTCDate("2020-04-01 10:00:00 UTC")
        val key = OpenPgpKeyBuilder(Policy.getInstance(), date)
            .buildV4Key(KeyType.EDDSA(EdDSACurve._Ed25519))
                .addUserId("Alice")
                .addUserAttribute(
                    PGPUserAttributeSubpacketVectorGenerator()
                        .apply { setImageAttribute(ImageAttribute.JPEG, byteArrayOf()) }
                        .generate())
                .addEncryptionSubkey(KeyType.XDH(XDHSpec._X25519))
                .addSigningSubkey(KeyType.EDDSA(EdDSACurve._Ed25519))
                .build(SecretKeyRingProtector.unprotectedKeys())
        println(PGPainless.asciiArmor(key))
    }

    @Test
    fun minimal() {
        val key = OpenPgpKeyBuilder(Policy.getInstance())
            .buildV4Key(KeyType.EDDSA(EdDSACurve._Ed25519))
            .build()
        println(PGPainless.asciiArmor(key))
    }

    @Test
    fun minimalWithUserId() {
        val key = OpenPgpKeyBuilder(Policy.getInstance())
            .buildV4Key(KeyType.EDDSA(EdDSACurve._Ed25519))
            .addUserId("Alice <alice@pgpainless.org>")
            .build()
        println(PGPainless.asciiArmor(key))
    }
}
