package org.pgpainless.key.generation

import org.junit.jupiter.api.Test
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.rsa.RsaLength
import org.pgpainless.policy.Policy

class OpenPgpV4KeyGeneratorTest {

    @Test
    fun test() {

        OpenPgpV4KeyGenerator(Policy.getInstance())

        OpenPgpV4KeyGenerator(Policy.getInstance())
            .primaryKey(
                KeyType.RSA(RsaLength._4096),
                KeyFlag.CERTIFY_OTHER
            ).signingSubkey(
                KeyType.RSA(RsaLength._4096)
            ).encryptionSubkey(
                KeyType.RSA(RsaLength._4096)
            )
    }
}
