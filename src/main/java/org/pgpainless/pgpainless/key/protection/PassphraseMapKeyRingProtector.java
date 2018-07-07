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
package org.pgpainless.pgpainless.key.protection;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.pgpainless.pgpainless.util.Passphrase;

/**
 * Implementation of the {@link SecretKeyRingProtector} which holds a map of key ids and their passwords.
 */
public class PassphraseMapKeyRingProtector implements SecretKeyRingProtector {

    private static final PGPDigestCalculatorProvider calculatorProvider = new BcPGPDigestCalculatorProvider();

    private final Map<Long, Passphrase> passphrases = new HashMap<>();
    private final KeyRingProtectionSettings protectionSettings;

    public PassphraseMapKeyRingProtector(Map<Long, Passphrase> passphrases, KeyRingProtectionSettings protectionSettings) {
        this.passphrases.putAll(passphrases);
        this.protectionSettings = protectionSettings;
    }

    public void addPassphrase(Long keyId, Passphrase passphrase) {
        this.passphrases.put(keyId, passphrase);
    }

    public void forgetPassphrase(Long keyId) {
        Passphrase passphrase = passphrases.get(keyId);
        passphrase.clear();
        passphrases.remove(keyId);
    }

    @Override
    public PBESecretKeyDecryptor getDecryptor(Long keyId) {
        Passphrase passphrase = passphrases.get(keyId);
        return new BcPBESecretKeyDecryptorBuilder(calculatorProvider)
                .build(passphrase != null ? passphrase.getChars() : null);
    }

    @Override
    public PBESecretKeyEncryptor getEncryptor(Long keyId) throws PGPException {
        Passphrase passphrase = passphrases.get(keyId);
        return new BcPBESecretKeyEncryptorBuilder(
                protectionSettings.getEncryptionAlgorithm().getAlgorithmId(),
                calculatorProvider.get(protectionSettings.getHashAlgorithm().getAlgorithmId()),
                protectionSettings.getS2kCount())
                .build(passphrase != null ? passphrase.getChars() : null);
    }
}
