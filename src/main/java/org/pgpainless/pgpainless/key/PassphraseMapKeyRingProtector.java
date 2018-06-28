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
package org.pgpainless.pgpainless.key;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;

/**
 * Implementation of the {@link SecretKeyRingProtector} which holds a map of key ids and their passwords.
 */
public class PassphraseMapKeyRingProtector implements SecretKeyRingProtector {

    private static final PGPDigestCalculatorProvider calculatorProvider = new BcPGPDigestCalculatorProvider();

    private final Map<Long, char[]> passphrases = new HashMap<>();
    private final KeyRingProtectionSettings protectionSettings;

    public PassphraseMapKeyRingProtector(Map<Long, char[]> passphrases, KeyRingProtectionSettings protectionSettings) {
        this.passphrases.putAll(passphrases);
        this.protectionSettings = protectionSettings;
    }

    public void addPassphrase(Long keyId, char[] passphrase) {
        this.passphrases.put(keyId, passphrase);
    }

    public void forgetPassphrase(Long keyId) {
        char[] passphrase = passphrases.get(keyId);
        // Overwrite the passphrase in memory with zeros
        for (int i = 0; i < passphrase.length; i++) {
            passphrase[i] = '0';
        }
        passphrases.remove(keyId);
    }

    @Override
    public PBESecretKeyDecryptor getDecryptor(Long keyId) {
        return new BcPBESecretKeyDecryptorBuilder(calculatorProvider).build(passphrases.get(keyId));
    }

    @Override
    public PBESecretKeyEncryptor getEncryptor(Long keyId) throws PGPException {
        return new BcPBESecretKeyEncryptorBuilder(
                protectionSettings.getEncryptionAlgorithm().getAlgorithmId(),
                calculatorProvider.get(protectionSettings.getHashAlgorithm().getAlgorithmId()),
                protectionSettings.getS2kCount())
                .build(passphrases.get(keyId));
    }
}
