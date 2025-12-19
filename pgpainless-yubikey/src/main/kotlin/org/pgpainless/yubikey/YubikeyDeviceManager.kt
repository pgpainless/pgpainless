// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.yubikey

import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.management.DeviceInfo

abstract class YubikeyDeviceManager {

    fun toYubikey(device: YubiKeyDevice, deviceInfo: DeviceInfo) = Yubikey(deviceInfo, device)

    abstract fun listDevices(): List<Yubikey>
}
