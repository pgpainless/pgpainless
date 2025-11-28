package org.pgpainless.yubikey

import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.openpgp.KeyRef
import com.yubico.yubikit.openpgp.OpenPgpSession
import org.gnupg.GnuPGDummyKeyUtil
import org.pgpainless.hardware.HardwareTokenBackend

class YubikeyHardwareTokenBackend : HardwareTokenBackend {

    override fun listDeviceSerials(): List<ByteArray> {
        return YubikeyHelper().listDevices()
            .mapNotNull { yk -> yk.info.serialNumber?.let { GnuPGDummyKeyUtil.serialToBytes(it) } }
    }

    override fun listKeyFingerprints(): Map<ByteArray, List<ByteArray>> {
        return YubikeyHelper().listDevices()
            .associate { yk ->
                yk.encodedSerial to yk.device.openConnection(SmartCardConnection::class.java).use {
                    val session = OpenPgpSession(it)
                    //6session.getData(KeyRef.DEC.fingerprint)
                    session.getData(KeyRef.SIG.fingerprint)


                    listOfNotNull(
                        session.getData(KeyRef.ATT.fingerprint),
                        session.getData(KeyRef.SIG.fingerprint),
                        session.getData(KeyRef.DEC.fingerprint),
                        session.getData(KeyRef.AUT.fingerprint)
                    )
                }
            }
    }
}
