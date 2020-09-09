/*
 * Copyright 2018 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.key.protection;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.pgpainless.util.Passphrase;

/**
 * Provides {@link PBESecretKeyDecryptor} and {@link PBESecretKeyEncryptor} objects while getting the passphrases
 * from a {@link SecretKeyPassphraseProvider} and using settings from an {@link KeyRingProtectionSettings}.
 */
public class PasswordBasedSecretKeyRingProtector implements SecretKeyRingProtector {

    private static final PGPDigestCalculatorProvider calculatorProvider = new BcPGPDigestCalculatorProvider();

    protected final KeyRingProtectionSettings protectionSettings;
    protected final SecretKeyPassphraseProvider passphraseProvider;

    /**
     * Constructor.
     * Passphrases for keys are sourced from the {@code passphraseProvider} and decryptors/encryptors are constructed
     * following the settings given in {@code settings}.
     *
     * @param settings S2K settings etc.
     * @param passphraseProvider provider which provides passphrases.
     */
    public PasswordBasedSecretKeyRingProtector(@Nonnull KeyRingProtectionSettings settings, @Nonnull SecretKeyPassphraseProvider passphraseProvider) {
        this.protectionSettings = settings;
        this.passphraseProvider = passphraseProvider;
    }

    public static PasswordBasedSecretKeyRingProtector forKey(PGPKeyRing keyRing, Passphrase passphrase) {
        KeyRingProtectionSettings protectionSettings = KeyRingProtectionSettings.secureDefaultSettings();
        SecretKeyPassphraseProvider passphraseProvider = new SecretKeyPassphraseProvider() {
            @Override
            @Nullable
            public Passphrase getPassphraseFor(Long keyId) {
                if (keyRing.getPublicKey().getKeyID() == keyId) {
                    return passphrase;
                }
                return null;
            }
        };
        return new PasswordBasedSecretKeyRingProtector(protectionSettings, passphraseProvider);
    }

    @Override
    @Nullable
    public PBESecretKeyDecryptor getDecryptor(Long keyId) {
        Passphrase passphrase = passphraseProvider.getPassphraseFor(keyId);
        return passphrase == null ? null :
                new BcPBESecretKeyDecryptorBuilder(calculatorProvider)
                        .build(passphrase.getChars());
    }

    @Override
    @Nullable
    public PBESecretKeyEncryptor getEncryptor(Long keyId) throws PGPException {
        Passphrase passphrase = passphraseProvider.getPassphraseFor(keyId);
        return passphrase == null ? null :
                new BcPBESecretKeyEncryptorBuilder(
                        protectionSettings.getEncryptionAlgorithm().getAlgorithmId(),
                        calculatorProvider.get(protectionSettings.getHashAlgorithm().getAlgorithmId()),
                        protectionSettings.getS2kCount())
                        .build(passphrase.getChars());
    }
}
