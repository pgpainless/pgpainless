// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.yubikey.desktop

import com.yubico.yubikit.desktop.CompositeDevice
import com.yubico.yubikit.desktop.YubiKitManager
import org.pgpainless.yubikey.Yubikey
import org.pgpainless.yubikey.YubikeyDeviceManager

class DesktopYubikeyDeviceManager(private val manager: YubiKitManager = YubiKitManager()) :
    YubikeyDeviceManager() {

    override fun listDevices(): List<Yubikey> =
        try {
            manager
                .listAllDevices()
                .filter { it.key is CompositeDevice }
                .map { toYubikey(it.key, it.value) }
        } catch (e: RuntimeException) {
            // If there are no tokens, yubikit throws a RuntimeException :/
            emptyList()
        }
}
