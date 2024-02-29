// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.bouncycastle.extensions.directKeySignatures
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.eddsa.EdDSACurve
import org.pgpainless.key.generation.type.xdh.XDHSpec
import org.pgpainless.policy.Policy

class KeyWithInacceptableSelfSignatureTest {

    @Test
    fun `key with inacceptable self-signature is not usable`() {
        val genPolicy =
            Policy().apply {
                certificationSignatureHashAlgorithmPolicy =
                    Policy.HashAlgorithmPolicy(HashAlgorithm.SHA1, listOf(HashAlgorithm.SHA1))
            }

        val key =
            PGPainless.generateOpenPgpKey(genPolicy)
                .buildV4Key()
                .setPrimaryKey(
                    KeyType.EDDSA(EdDSACurve._Ed25519),
                    listOf(KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA))
                .addEncryptionSubkey(KeyType.XDH(XDHSpec._X25519))
                .build()

        assertEquals(
            HashAlgorithm.SHA1,
            key.publicKey.directKeySignatures.single().hashAlgorithm.let {
                HashAlgorithm.requireFromId(it)
            })

        val info = PGPainless.inspectKeyRing(key)
        assertFalse(info.isUsableForSigning)
        assertFalse(info.isUsableForEncryption)
    }
}
