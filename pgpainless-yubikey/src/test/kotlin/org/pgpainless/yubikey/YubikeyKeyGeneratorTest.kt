// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.yubikey

import java.util.*
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.OpenPGPKeyVersion

class YubikeyKeyGeneratorTest : YubikeyTest() {

    @Test
    fun generateKey() {
        val backend = YubikeyHardwareTokenBackend()
        val keyGen = YubikeyKeyGenerator(PGPainless.getInstance())
        val key = keyGen.generateModernKey(yubikey, adminPin, OpenPGPKeyVersion.v4, Date())

        println(key.toAsciiArmoredString())
        // TODO: More thorough checking once key generation is implemented with binding signatures,
        //  userids and other metadata
        val fingerprints = backend.listKeyFingerprints().entries.first().value
        for (subkey in key.secretKeys) {
            assertTrue(subkey.value.hasExternalSecretKey())
            assertTrue {
                fingerprints.any { it.contentEquals(subkey.value.pgpPublicKey.fingerprint) }
            }
        }
    }
}
