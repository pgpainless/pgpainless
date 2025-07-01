// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection

import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.api.OpenPGPCertificate
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
            cert: OpenPGPCertificate,
            passphrase: Passphrase
        ): PasswordBasedSecretKeyRingProtector {
            return object : SecretKeyPassphraseProvider {

                    override fun getPassphraseFor(keyIdentifier: KeyIdentifier): Passphrase? {
                        return if (hasPassphrase(keyIdentifier)) passphrase else null
                    }

                    override fun hasPassphrase(keyIdentifier: KeyIdentifier): Boolean {
                        return cert.getKey(keyIdentifier) != null
                    }
                }
                .let { PasswordBasedSecretKeyRingProtector(it) }
        }

        @JvmStatic
        fun forKey(
            keyRing: PGPKeyRing,
            passphrase: Passphrase
        ): PasswordBasedSecretKeyRingProtector {
            return object : SecretKeyPassphraseProvider {

                    override fun getPassphraseFor(keyIdentifier: KeyIdentifier): Passphrase? {
                        return if (hasPassphrase(keyIdentifier)) passphrase else null
                    }

                    override fun hasPassphrase(keyIdentifier: KeyIdentifier): Boolean {
                        return keyRing.getPublicKey(keyIdentifier) != null
                    }
                }
                .let { PasswordBasedSecretKeyRingProtector(it) }
        }

        @JvmStatic
        fun forKey(key: PGPSecretKey, passphrase: Passphrase): PasswordBasedSecretKeyRingProtector =
            forKeyId(key.publicKey.keyIdentifier, passphrase)

        @JvmStatic
        fun forKeyId(
            singleKeyIdentifier: KeyIdentifier,
            passphrase: Passphrase
        ): PasswordBasedSecretKeyRingProtector {
            return object : SecretKeyPassphraseProvider {
                    override fun getPassphraseFor(keyIdentifier: KeyIdentifier): Passphrase? {
                        return if (hasPassphrase(keyIdentifier)) passphrase else null
                    }

                    override fun hasPassphrase(keyIdentifier: KeyIdentifier): Boolean {
                        return keyIdentifier.matchesExplicit(singleKeyIdentifier)
                    }
                }
                .let { PasswordBasedSecretKeyRingProtector(it) }
        }
    }
}
