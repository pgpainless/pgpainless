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
        val keyGen = YubikeyKeyGenerator(PGPainless.getInstance())
        val key = keyGen.generateModernKey(yubikey, adminPin, OpenPGPKeyVersion.v4, Date())

        println(key.toAsciiArmoredString())
        for (subkey in key.secretKeys) {
            assertTrue(subkey.value.hasExternalSecretKey())
        }
    }
}
