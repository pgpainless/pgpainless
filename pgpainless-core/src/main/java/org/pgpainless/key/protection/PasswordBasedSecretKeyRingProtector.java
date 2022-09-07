// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider;
import org.pgpainless.s2k.Passphrase;

/**
 * Provides {@link PBESecretKeyDecryptor} and {@link PBESecretKeyEncryptor} objects while getting the passphrases
 * from a {@link SecretKeyPassphraseProvider} and using settings from an {@link KeyRingProtectionSettings}.
 */
public class PasswordBasedSecretKeyRingProtector extends BaseSecretKeyRingProtector {

    public PasswordBasedSecretKeyRingProtector(@Nonnull SecretKeyPassphraseProvider passphraseProvider) {
        super(passphraseProvider);
    }

    /**
     * Constructor.
     * Passphrases for keys are sourced from the {@code passphraseProvider} and decryptors/encryptors are constructed
     * following the settings given in {@code settings}.
     *
     * @param settings S2K settings etc.
     * @param passphraseProvider provider which provides passphrases.
     */
    public PasswordBasedSecretKeyRingProtector(@Nonnull KeyRingProtectionSettings settings, @Nonnull SecretKeyPassphraseProvider passphraseProvider) {
        super(passphraseProvider, settings);
    }

    public static PasswordBasedSecretKeyRingProtector forKey(PGPKeyRing keyRing, Passphrase passphrase) {
        SecretKeyPassphraseProvider passphraseProvider = new SecretKeyPassphraseProvider() {
            @Override
            @Nullable
            public Passphrase getPassphraseFor(Long keyId) {
                return hasPassphrase(keyId) ? passphrase : null;
            }

            @Override
            public boolean hasPassphrase(Long keyId) {
                return keyRing.getPublicKey(keyId) != null;
            }
        };
        return new PasswordBasedSecretKeyRingProtector(passphraseProvider);
    }

    public static PasswordBasedSecretKeyRingProtector forKey(PGPSecretKey key, Passphrase passphrase) {
        return forKeyId(key.getPublicKey().getKeyID(), passphrase);
    }

    public static PasswordBasedSecretKeyRingProtector forKeyId(long singleKeyId, Passphrase passphrase) {
        SecretKeyPassphraseProvider passphraseProvider = new SecretKeyPassphraseProvider() {
            @Nullable
            @Override
            public Passphrase getPassphraseFor(Long keyId) {
                if (keyId == singleKeyId) {
                    return passphrase;
                }
                return null;
            }

            @Override
            public boolean hasPassphrase(Long keyId) {
                return keyId == singleKeyId;
            }
        };
        return new PasswordBasedSecretKeyRingProtector(passphraseProvider);
    }

}
