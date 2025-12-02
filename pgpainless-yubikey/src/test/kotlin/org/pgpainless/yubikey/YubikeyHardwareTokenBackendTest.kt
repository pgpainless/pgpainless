// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.yubikey

import org.gnupg.GnuPGDummyKeyUtil
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test

class YubikeyHardwareTokenBackendTest : YubikeyTest() {

    val backend = YubikeyHardwareTokenBackend()

    @Test
    fun testListDeviceSerials() {
        val serials = backend.listDeviceSerials()
        assertTrue(
            serials.any { it.contentEquals(GnuPGDummyKeyUtil.serialToBytes(allowedSerialNumber)) })
    }

    @Test
    @Disabled("because yubikit-android 2.9.0 cannot extract fingerprints")
    fun testListKeys() {
        val keys = backend.listKeyFingerprints()
        assumeTrue(keys.isNotEmpty())
    }
}
