package org.pgpainless.yubikey

import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.keys.PrivateKeyValues
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.management.DeviceInfo
import com.yubico.yubikit.openpgp.KeyRef
import com.yubico.yubikit.openpgp.OpenPgpSession
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPPrivateKey
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter
import org.gnupg.GnuPGDummyKeyUtil

data class Yubikey(val info: DeviceInfo, val device: YubiKeyDevice) {
    fun storeKeyInSlot(key: OpenPGPPrivateKey, keyRef: KeyRef, adminPin: CharArray) {
        device.openConnection(SmartCardConnection::class.java).use {
            // Extract private key
            val privateKey = JcaPGPKeyConverter().setProvider(BouncyCastleProvider())
            .getPrivateKey(key.keyPair.privateKey)

            val session = OpenPgpSession(it as SmartCardConnection)

            // Storing keys requires admin pin
            session.verifyAdminPin(adminPin)

            session.putKey(keyRef, PrivateKeyValues.fromPrivateKey(privateKey))
            val fp = key.publicKey.pgpPublicKey.fingerprint
            session.setFingerprint(keyRef, fp)
            val time = (key.publicKey.pgpPublicKey.publicKeyPacket.time.time / 1000).toInt()
            session.setGenerationTime(keyRef, time)
        }
    }

    val encodedSerial = GnuPGDummyKeyUtil.serialToBytes(info.serialNumber!!)
}
