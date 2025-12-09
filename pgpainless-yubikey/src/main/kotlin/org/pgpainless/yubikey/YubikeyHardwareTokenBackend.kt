// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

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
        return object : Iterator<PublicKeyDataDecryptorFactory> {
            val devices = YubikeyHelper().listDevices().iterator()

            override fun hasNext(): Boolean {
                return devices.hasNext()
            }

            override fun next(): PublicKeyDataDecryptorFactory {
                return devices.next().device.openConnection(SmartCardConnection::class.java).let {
                    val decFac =
                        YubikeyDataDecryptorFactory.createDecryptorFromConnection(
                            it, secKey.pgpPublicKey)
                    decFac as PublicKeyDataDecryptorFactory
                }
            }
        }
    }

    override fun listDeviceSerials(): List<ByteArray> {
        return YubikeyHelper().listDevices().mapNotNull { yk ->
            yk.info.serialNumber?.let { GnuPGDummyKeyUtil.serialToBytes(it) }
        }
    }

    override fun listKeyFingerprints(): Map<ByteArray, List<ByteArray>> {
        return YubikeyHelper().listDevices().associate { yk ->
            yk.encodedSerialNumber to yk.openSession().use {
                // session.getData(KeyRef.DEC.fingerprint)
                val ddo = it.applicationRelatedData.discretionary

                listOfNotNull(
                    ddo.getFingerprint(KeyRef.ATT),
                    ddo.getFingerprint(KeyRef.SIG),
                    ddo.getFingerprint(KeyRef.DEC),
                    ddo.getFingerprint(KeyRef.AUT))
            }
        }
    }
}
