// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.yubikey

import org.gnupg.GnuPGDummyKeyUtil
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.pgpainless.yubikey.desktop.DesktopYubikeyDeviceManager

class YubikeyHardwareTokenBackendTest : YubikeyTest() {

    val backend = YubikeyHardwareTokenBackend(DesktopYubikeyDeviceManager())

    @Test
    fun testListDeviceSerials() {
        val serials = backend.listDeviceSerials()
        assertTrue(
            serials.any { it.contentEquals(GnuPGDummyKeyUtil.serialToBytes(allowedSerialNumber)) })
    }

    @Test
    fun testListKeys() {
        val keys = backend.listKeyFingerprints()
        assumeTrue(keys.isNotEmpty())
    }
}
