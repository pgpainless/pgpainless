// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation

import org.bouncycastle.bcpg.sig.Exportable
import org.bouncycastle.bcpg.sig.PrimaryUserID
import org.bouncycastle.bcpg.sig.Revocable
import org.junit.jupiter.api.Test
import org.pgpainless.PGPainless
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.eddsa.EdDSACurve
import org.pgpainless.policy.Policy
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets

class MalformedKeyGenerationTest {

    @Test
    fun malformedPrimaryUserIdSubpacket() {
        val userId = "Alice <alice@pgpainless.org>"
        val key =
            GenerateOpenPgpKey(Policy.getInstance())
                .buildV4Key(KeyType.EDDSA(EdDSACurve._Ed25519))
                .addUserId(
                    userId,
                    SelfSignatureSubpackets.applyHashed {
                        setPrimaryUserId(PrimaryUserID(false, false, byteArrayOf(0x02)))
                    })
                .build()

        println(PGPainless.asciiArmor(key))

        PGPainless.readKeyRing().secretKeyRing(key.encoded)!!
        // TODO: Check interpretation of faulty PrimaryUserID packet
    }

    @Test
    fun malformedExportableSubpacket() {
        val key =
            GenerateOpenPgpKey(Policy.getInstance())
                .buildV4Key(KeyType.EDDSA(EdDSACurve._Ed25519))
                .addUserId(
                    "Alice <alice@pgpainless.org>",
                    SelfSignatureSubpackets.applyHashed {
                        setExportable(Exportable(false, false, byteArrayOf(0x03)))
                    })
                .build()

        println(PGPainless.asciiArmor(key))

        PGPainless.readKeyRing().secretKeyRing(key.encoded)!!
        // TODO: Check interpretation of faulty packet
    }

    @Test
    fun malformedRevocableSubpacket() {
        val key =
            GenerateOpenPgpKey(Policy.getInstance())
                .buildV4Key(KeyType.EDDSA(EdDSACurve._Ed25519))
                .addUserId(
                    "Alice <alice@pgpainless.org>",
                    SelfSignatureSubpackets.applyHashed {
                        setRevocable(Revocable(false, false, byteArrayOf(0x04)))
                    })
                .build()

        println(PGPainless.asciiArmor(key))

        PGPainless.readKeyRing().secretKeyRing(key.encoded)!!
        // TODO: Check interpretation of faulty packet
    }
}
