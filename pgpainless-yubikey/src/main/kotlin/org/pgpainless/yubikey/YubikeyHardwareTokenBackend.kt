// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.yubikey

import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.openpgp.KeyRef
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory
import org.gnupg.GnuPGDummyKeyUtil
import org.pgpainless.hardware.HardwareKey
import org.pgpainless.hardware.HardwareToken
import org.pgpainless.hardware.HardwareTokenBackend
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider

class YubikeyHardwareTokenBackend(private val deviceManager: YubikeyDeviceManager) :
    HardwareTokenBackend {

    override fun getBackendName(): String {
        return "PGPainless-Yubikey"
    }

    override fun provideDecryptorsFor(
        secKey: OpenPGPKey.OpenPGPSecretKey,
        passphraseProvider: SecretKeyPassphraseProvider,
        pkesk: PGPPublicKeyEncryptedData
    ): Iterator<PublicKeyDataDecryptorFactory> {
        return object : Iterator<PublicKeyDataDecryptorFactory> {
            val devices = deviceManager.listDevices().iterator()

            override fun hasNext(): Boolean {
                return devices.hasNext()
            }

            override fun next(): PublicKeyDataDecryptorFactory {
                return devices.next().device.openConnection(SmartCardConnection::class.java).let {
                    val decFac =
                        YubikeyDataDecryptorFactory.createDecryptorFromConnection(
                            it, secKey.pgpPublicKey, passphraseProvider)
                    decFac as PublicKeyDataDecryptorFactory
                }
            }
        }
    }

    override fun listKeys(): Map<ByteArray, HardwareToken> {
        return deviceManager.listDevices().associate { device ->
            device.encodedSerialNumber to
                device.openSession().use { session ->
                    // Retrieve fingerprints of keys on the device
                    val ddo = session.applicationRelatedData.discretionary
                    HardwareToken(
                        listOf(KeyRef.ATT, KeyRef.SIG, KeyRef.DEC, KeyRef.AUT)
                            .associateWith { keyRef -> ddo.getFingerprint(keyRef) }
                            .filter { it.value != null } // filter out empty fingerprints
                            .map { it.value!! to HardwareKey(it.value!!, it.key) }
                            .toMap())
                }
        }
    }

    override fun listDeviceSerials(): List<ByteArray> {
        return deviceManager.listDevices().mapNotNull { yk ->
            yk.info.serialNumber?.let { GnuPGDummyKeyUtil.serialToBytes(it) }
        }
    }

    override fun listKeyFingerprints(): Map<ByteArray, List<ByteArray>> {
        return listKeys().map { e -> e.key to e.value.keys.keys.toList() }.toMap()
    }
}
