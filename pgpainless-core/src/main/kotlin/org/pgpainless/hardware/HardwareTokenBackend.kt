package org.pgpainless.hardware

interface HardwareTokenBackend {
    fun listDeviceSerials(): List<ByteArray>

    fun listKeyFingerprints(): Map<ByteArray, List<ByteArray>>
}
