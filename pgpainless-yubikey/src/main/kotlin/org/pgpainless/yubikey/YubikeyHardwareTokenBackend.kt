package org.pgpainless.yubikey

import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.openpgp.KeyRef
import com.yubico.yubikit.openpgp.OpenPgpSession
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory
import org.gnupg.GnuPGDummyKeyUtil
import org.pgpainless.hardware.HardwareTokenBackend
import org.pgpainless.key.protection.SecretKeyRingProtector

class YubikeyHardwareTokenBackend : HardwareTokenBackend {

    override fun getBackendName(): String {
        return "PGPainless-Yubikey"
    }

    override fun provideDecryptorsFor(
        secKey: OpenPGPKey.OpenPGPSecretKey,
        protector: SecretKeyRingProtector,
        pkesk: PGPPublicKeyEncryptedData
    ): Iterator<PublicKeyDataDecryptorFactory> {
        val devices = YubikeyHelper().listDevices()
        return devices.map { yubikey ->
            yubikey.device.openConnection(SmartCardConnection::class.java).use {
                val decFac = YubikeyDataDecryptorFactory.createDecryptorFromConnection(
                    it,
                    secKey.pgpPublicKey
                )
                decFac as PublicKeyDataDecryptorFactory
            }
        }.iterator()
    }

    override fun listDeviceSerials(): List<ByteArray> {
        return YubikeyHelper().listDevices()
            .mapNotNull { yk -> yk.info.serialNumber?.let { GnuPGDummyKeyUtil.serialToBytes(it) } }
    }

    override fun listKeyFingerprints(): Map<ByteArray, List<ByteArray>> {
        return YubikeyHelper().listDevices()
            .associate { yk ->
                yk.encodedSerialNumber to yk.device.openConnection(SmartCardConnection::class.java).use {
                    val session = OpenPgpSession(it)
                    //session.getData(KeyRef.DEC.fingerprint)
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
