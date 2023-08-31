// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider;
import org.pgpainless.util.Passphrase;

import javax.annotation.Nullable;

/**
 * Basic {@link SecretKeyRingProtector} implementation that respects the users {@link KeyRingProtectionSettings} when
 * encrypting keys.
 */
public class BaseSecretKeyRingProtector implements SecretKeyRingProtector {

    private final SecretKeyPassphraseProvider passphraseProvider;
    private final KeyRingProtectionSettings protectionSettings;

    /**
     * Constructor that uses the given {@link SecretKeyPassphraseProvider} to retrieve passphrases and PGPainless'
     * default {@link KeyRingProtectionSettings}.
     *
     * @param passphraseProvider provider for passphrases
     */
    public BaseSecretKeyRingProtector(SecretKeyPassphraseProvider passphraseProvider) {
        this(passphraseProvider, KeyRingProtectionSettings.secureDefaultSettings());
    }

    /**
     * Constructor that uses the given {@link SecretKeyPassphraseProvider} and {@link KeyRingProtectionSettings}.
     *
     * @param passphraseProvider provider for passphrases
     * @param protectionSettings protection settings
     */
    public BaseSecretKeyRingProtector(SecretKeyPassphraseProvider passphraseProvider, KeyRingProtectionSettings protectionSettings) {
        this.passphraseProvider = passphraseProvider;
        this.protectionSettings = protectionSettings;
    }

    @Override
    public boolean hasPassphraseFor(long keyId) {
        return passphraseProvider.hasPassphrase(keyId);
    }

    @Override
    @Nullable
    public PBESecretKeyDecryptor getDecryptor(long keyId) throws PGPException {
        Passphrase passphrase = passphraseProvider.getPassphraseFor(keyId);
        return passphrase == null || passphrase.isEmpty() ? null :
                ImplementationFactory.getInstance().getPBESecretKeyDecryptor(passphrase);
    }

    @Override
    @Nullable
    public PBESecretKeyEncryptor getEncryptor(long keyId) throws PGPException {
        Passphrase passphrase = passphraseProvider.getPassphraseFor(keyId);
        return passphrase == null || passphrase.isEmpty() ? null :
                ImplementationFactory.getInstance().getPBESecretKeyEncryptor(
                        protectionSettings.getEncryptionAlgorithm(),
                        protectionSettings.getHashAlgorithm(),
                        protectionSettings.getS2kCount(),
                        passphrase);
    }
}
