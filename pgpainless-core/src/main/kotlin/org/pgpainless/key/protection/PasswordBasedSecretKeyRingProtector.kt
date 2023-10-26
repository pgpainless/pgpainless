// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection

import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider
import org.pgpainless.util.Passphrase

/**
 * Provides [PBESecretKeyDecryptor] and [PBESecretKeyEncryptor] objects while getting the
 * passphrases from a [SecretKeyPassphraseProvider] and using settings from an
 * [KeyRingProtectionSettings].
 */
class PasswordBasedSecretKeyRingProtector : BaseSecretKeyRingProtector {

    constructor(passphraseProvider: SecretKeyPassphraseProvider) : super(passphraseProvider)

    /**
     * Constructor. Passphrases for keys are sourced from the `passphraseProvider` and
     * decryptors/encryptors are constructed following the settings given in `settings`.
     *
     * @param settings S2K settings etc.
     * @param passphraseProvider provider which provides passphrases.
     */
    constructor(
        settings: KeyRingProtectionSettings,
        passphraseProvider: SecretKeyPassphraseProvider
    ) : super(passphraseProvider, settings)

    companion object {
        @JvmStatic
        fun forKey(
            keyRing: PGPKeyRing,
            passphrase: Passphrase
        ): PasswordBasedSecretKeyRingProtector {
            return object : SecretKeyPassphraseProvider {

                    override fun getPassphraseFor(keyId: Long): Passphrase? {
                        return if (hasPassphrase(keyId)) passphrase else null
                    }

                    override fun hasPassphrase(keyId: Long): Boolean {
                        return keyRing.getPublicKey(keyId) != null
                    }
                }
                .let { PasswordBasedSecretKeyRingProtector(it) }
        }

        @JvmStatic
        fun forKey(key: PGPSecretKey, passphrase: Passphrase): PasswordBasedSecretKeyRingProtector =
            forKeyId(key.publicKey.keyID, passphrase)

        @JvmStatic
        fun forKeyId(
            singleKeyId: Long,
            passphrase: Passphrase
        ): PasswordBasedSecretKeyRingProtector {
            return object : SecretKeyPassphraseProvider {
                    override fun getPassphraseFor(keyId: Long): Passphrase? {
                        return if (hasPassphrase(keyId)) passphrase else null
                    }

                    override fun hasPassphrase(keyId: Long): Boolean {
                        return keyId == singleKeyId
                    }
                }
                .let { PasswordBasedSecretKeyRingProtector(it) }
        }
    }
}
