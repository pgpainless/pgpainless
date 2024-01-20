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

class OpenPgpV4KeyGeneratorTest {

    @Test
    fun test() {
        val date = DateUtil.parseUTCDate("2020-04-01 10:00:00 UTC")
        val key =
            OpenPgpV4KeyGenerator(
                    KeyType.EDDSA(EdDSACurve._Ed25519), Policy.getInstance(), referenceTime = date)
                .addUserId("Alice")
                .addUserAttribute(
                    PGPUserAttributeSubpacketVectorGenerator().apply {
                        setImageAttribute(ImageAttribute.JPEG, byteArrayOf())
                    }.generate())
                .addEncryptionSubkey(KeyType.XDH(XDHSpec._X25519))
                .addSigningSubkey(KeyType.EDDSA(EdDSACurve._Ed25519))
                .build(SecretKeyRingProtector.unprotectedKeys())
        println(PGPainless.asciiArmor(key))
    }
}
