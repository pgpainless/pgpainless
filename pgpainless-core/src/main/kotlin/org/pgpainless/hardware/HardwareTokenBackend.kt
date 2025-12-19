// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.hardware

import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider

interface HardwareTokenBackend {

    fun getBackendName(): String

    fun provideDecryptorsFor(
        secKey: OpenPGPKey.OpenPGPSecretKey,
        passphraseProvider: SecretKeyPassphraseProvider,
        pkesk: PGPPublicKeyEncryptedData
    ): Iterator<PublicKeyDataDecryptorFactory>

    fun listKeys(): Map<ByteArray, HardwareToken>

    fun listDeviceSerials(): List<ByteArray>

    fun listKeyFingerprints(): Map<ByteArray, List<ByteArray>>
}
