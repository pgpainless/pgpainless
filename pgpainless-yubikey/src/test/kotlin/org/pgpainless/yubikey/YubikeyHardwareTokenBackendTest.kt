package org.pgpainless.yubikey

import org.gnupg.GnuPGDummyKeyUtil
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.util.Arrays

class YubikeyHardwareTokenBackendTest : YubikeyTest() {

    val backend = YubikeyHardwareTokenBackend()

    @Test
    fun testListDeviceSerials() {
        val serials = backend.listDeviceSerials()
        assertTrue(serials.any {
            it.contentEquals(
                GnuPGDummyKeyUtil.serialToBytes(
                    allowedSerialNumber
                )
            )
        })
    }

    @Test
    fun testListKeys() {
        val keys = backend.listKeyFingerprints()
        assumeTrue(keys.isNotEmpty())
    }
}
