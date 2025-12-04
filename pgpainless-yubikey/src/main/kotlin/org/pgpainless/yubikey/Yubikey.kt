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

    fun storeKeyInSlot(key: OpenPGPPrivateKey, keyRef: KeyRef, adminPin: CharArray) {
        device.openConnection(SmartCardConnection::class.java).use {
            val session = OpenPgpSession(it as SmartCardConnection)

            // Storing keys requires admin pin
            session.verifyAdminPin(adminPin)

            session.writePrivateKey(key, keyRef)
            session.writeFingerprint(key.publicKey, keyRef)
            session.writeGenerationTime(key.publicKey, keyRef)
        }
    }

    val serialNumber: Int = info.serialNumber!!

    val encodedSerialNumber = GnuPGDummyKeyUtil.serialToBytes(serialNumber)
}
