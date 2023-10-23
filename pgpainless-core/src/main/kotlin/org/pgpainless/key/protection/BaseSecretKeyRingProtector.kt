// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection

import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor
import org.pgpainless.implementation.ImplementationFactory
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

    override fun hasPassphraseFor(keyId: Long): Boolean = passphraseProvider.hasPassphrase(keyId)

    override fun getDecryptor(keyId: Long): PBESecretKeyDecryptor? =
        passphraseProvider.getPassphraseFor(keyId)?.let {
            if (it.isEmpty) null
            else ImplementationFactory.getInstance().getPBESecretKeyDecryptor(it)
        }

    override fun getEncryptor(keyId: Long): PBESecretKeyEncryptor? =
        passphraseProvider.getPassphraseFor(keyId)?.let {
            if (it.isEmpty) null
            else
                ImplementationFactory.getInstance()
                    .getPBESecretKeyEncryptor(
                        protectionSettings.encryptionAlgorithm,
                        protectionSettings.hashAlgorithm,
                        protectionSettings.s2kCount,
                        it)
        }
}
