package org.pgpainless.key.generation

import org.junit.jupiter.api.Test
import org.pgpainless.PGPainless
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.ecc.EllipticCurve
import org.pgpainless.key.generation.type.eddsa.EdDSACurve
import org.pgpainless.key.generation.type.rsa.RsaLength
import org.pgpainless.key.generation.type.xdh.XDHSpec
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.policy.Policy

class OpenPgpV4KeyGeneratorTest {

    @Test
    fun test() {
        println(PGPainless.asciiArmor(
        OpenPgpV4KeyGenerator(KeyType.EDDSA(EdDSACurve._Ed25519), Policy.getInstance())
            .addUserId("Alice")
            .addEncryptionSubkey(KeyType.XDH(XDHSpec._X25519))
            .build(SecretKeyRingProtector.unprotectedKeys())
        ))
    }
}
