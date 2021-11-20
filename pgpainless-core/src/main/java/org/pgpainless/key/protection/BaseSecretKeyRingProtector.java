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

public class BaseSecretKeyRingProtector implements SecretKeyRingProtector {

    private final SecretKeyPassphraseProvider passphraseProvider;
    private final KeyRingProtectionSettings protectionSettings;

    public BaseSecretKeyRingProtector(SecretKeyPassphraseProvider passphraseProvider) {
        this(passphraseProvider, KeyRingProtectionSettings.secureDefaultSettings());
    }

    public BaseSecretKeyRingProtector(SecretKeyPassphraseProvider passphraseProvider, KeyRingProtectionSettings protectionSettings) {
        this.passphraseProvider = passphraseProvider;
        this.protectionSettings = protectionSettings;
    }

    @Override
    public boolean hasPassphraseFor(Long keyId) {
        return passphraseProvider.hasPassphrase(keyId);
    }

    @Override
    @Nullable
    public PBESecretKeyDecryptor getDecryptor(Long keyId) throws PGPException {
        Passphrase passphrase = passphraseProvider.getPassphraseFor(keyId);
        return passphrase == null ? null :
                ImplementationFactory.getInstance().getPBESecretKeyDecryptor(passphrase);
    }

    @Override
    @Nullable
    public PBESecretKeyEncryptor getEncryptor(Long keyId) throws PGPException {
        Passphrase passphrase = passphraseProvider.getPassphraseFor(keyId);
        return passphrase == null ? null :
                ImplementationFactory.getInstance().getPBESecretKeyEncryptor(
                        protectionSettings.getEncryptionAlgorithm(),
                        protectionSettings.getHashAlgorithm(),
                        protectionSettings.getS2kCount(),
                        passphrase);
    }
}
