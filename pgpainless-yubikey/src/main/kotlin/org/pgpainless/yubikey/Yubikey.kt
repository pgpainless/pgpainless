// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.yubikey

import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.management.DeviceInfo
import com.yubico.yubikit.openpgp.KeyRef
import com.yubico.yubikit.openpgp.OpenPgpSession
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPPrivateKey
import org.gnupg.GnuPGDummyKeyUtil

data class Yubikey(val info: DeviceInfo, val device: YubiKeyDevice) {

    fun openSession(): OpenPgpSession {
        return OpenPgpSession(device.openConnection(SmartCardConnection::class.java))
    }

    fun factoryReset() {
        openSession().use { it.reset() }
    }

    fun storeKeyInSlot(key: OpenPGPPrivateKey, keyRef: KeyRef, adminPin: CharArray) {
        openSession().use {
            // Storing keys requires admin pin
            it.verifyAdminPin(adminPin)

            it.writePrivateKey(key, keyRef)
            it.writeFingerprint(key.publicKey, keyRef)
            it.writeGenerationTime(key.publicKey, keyRef)
        }
    }

    fun keyRefForFingerprint(fingerprint: ByteArray): KeyRef? {
        return getFingerprints().entries.find { it.value?.contentEquals(fingerprint) ?: false }?.key
    }

    fun getFingerprints(): Map<KeyRef, ByteArray?> {
        return openSession().use {
            // session.getData(KeyRef.DEC.fingerprint)
            val ddo = it.applicationRelatedData.discretionary

            buildMap {
                put(KeyRef.ATT, ddo.getFingerprint(KeyRef.ATT))
                put(KeyRef.SIG, ddo.getFingerprint(KeyRef.SIG))
                put(KeyRef.DEC, ddo.getFingerprint(KeyRef.DEC))
                put(KeyRef.AUT, ddo.getFingerprint(KeyRef.AUT))
            }
        }
    }

    val serialNumber: Int = info.serialNumber!!

    val encodedSerialNumber = GnuPGDummyKeyUtil.serialToBytes(serialNumber)
}
