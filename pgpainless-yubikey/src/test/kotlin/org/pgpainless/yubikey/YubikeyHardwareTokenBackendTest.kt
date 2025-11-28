package org.pgpainless.yubikey

import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test

class YubikeyHardwareTokenBackendTest {

    val backend = YubikeyHardwareTokenBackend()

    @Test
    fun testListDeviceSerials() {
        assertNotNull(backend.listDeviceSerials())
        assumeTrue(backend.listDeviceSerials().isNotEmpty())
    }

    @Test
    fun testListKeys() {
        val keys = backend.listKeyFingerprints()
        assumeTrue(keys.isNotEmpty())
    }
}
