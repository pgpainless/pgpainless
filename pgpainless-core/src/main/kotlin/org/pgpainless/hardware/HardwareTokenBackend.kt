// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.hardware

import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory
import org.pgpainless.key.protection.SecretKeyRingProtector

interface HardwareTokenBackend {

    fun getBackendName(): String

    fun provideDecryptorsFor(
        secKey: OpenPGPKey.OpenPGPSecretKey,
        protector: SecretKeyRingProtector,
        pkesk: PGPPublicKeyEncryptedData
    ): Iterator<PublicKeyDataDecryptorFactory>

    fun listDeviceSerials(): List<ByteArray>

    fun listKeyFingerprints(): Map<ByteArray, List<ByteArray>>
}
