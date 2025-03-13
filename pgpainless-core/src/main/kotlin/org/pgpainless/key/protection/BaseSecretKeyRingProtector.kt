// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection

import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.api.OpenPGPImplementation
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider

/**
 * Basic [SecretKeyRingProtector] implementation that respects the users [KeyRingProtectionSettings]
 * when encrypting keys.
 */
open class BaseSecretKeyRingProtector(
    private val passphraseProvider: SecretKeyPassphraseProvider,
    private val protectionSettings: KeyRingProtectionSettings
) : SecretKeyRingProtector {

    constructor(
        passphraseProvider: SecretKeyPassphraseProvider
    ) : this(passphraseProvider, KeyRingProtectionSettings.secureDefaultSettings())

    override fun hasPassphraseFor(keyIdentifier: KeyIdentifier): Boolean {
        return passphraseProvider.hasPassphrase(keyIdentifier)
    }

    override fun getDecryptor(keyId: Long): PBESecretKeyDecryptor? =
        getDecryptor(KeyIdentifier(keyId))

    override fun getDecryptor(keyIdentifier: KeyIdentifier): PBESecretKeyDecryptor? =
        passphraseProvider.getPassphraseFor(keyIdentifier)?.let {
            if (it.isEmpty) null
            else
                OpenPGPImplementation.getInstance()
                    .pbeSecretKeyDecryptorBuilderProvider()
                    .provide()
                    .build(it.getChars())
        }

    override fun getEncryptor(key: PGPPublicKey): PBESecretKeyEncryptor? {
        return passphraseProvider.getPassphraseFor(key.keyIdentifier)?.let {
            if (it.isEmpty) null
            else
                OpenPGPImplementation.getInstance()
                    .pbeSecretKeyEncryptorFactory(
                        false,
                        protectionSettings.encryptionAlgorithm.algorithmId,
                        protectionSettings.s2kCount)
                    .build(it.getChars(), key.publicKeyPacket)
        }
    }

    override fun getKeyPassword(p0: OpenPGPKey.OpenPGPSecretKey): CharArray? {
        return passphraseProvider.getPassphraseFor(p0.keyIdentifier)?.getChars()
    }
}
