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

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.pgpainless.util.Passphrase;

/**
 * Implementation of the {@link SecretKeyRingProtector} which holds a map of key ids and their passwords.
 * In case the needed passphrase is not contained in the map, the {@code missingPassphraseCallback} will be consulted,
 * and the passphrase is added to the map.
 */
public class PassphraseMapKeyRingProtector implements SecretKeyRingProtector, SecretKeyPassphraseProvider {

    private final Map<Long, Passphrase> cache = new HashMap<>();
    private final SecretKeyRingProtector protector;
    private final SecretKeyPassphraseProvider provider;

    public PassphraseMapKeyRingProtector(Map<Long, Passphrase> passphrases,
                                         KeyRingProtectionSettings protectionSettings,
                                         SecretKeyPassphraseProvider missingPassphraseCallback) {
        this.cache.putAll(passphrases);
        this.protector = new PasswordBasedSecretKeyRingProtector(protectionSettings, this);
        this.provider = missingPassphraseCallback;
    }

    /**
     * Add a passphrase to the cache.
     *
     * @param keyId id of the key
     * @param passphrase passphrase
     */
    public void addPassphrase(Long keyId, Passphrase passphrase) {
        this.cache.put(keyId, passphrase);
    }

    /**
     * Remove a passphrase from the cache.
     * The passphrase will be cleared and then removed.
     *
     * @param keyId id of the key
     */
    public void forgetPassphrase(Long keyId) {
        Passphrase passphrase = cache.get(keyId);
        passphrase.clear();
        cache.remove(keyId);
    }

    @Override
    public Passphrase getPassphraseFor(Long keyId) {
        Passphrase passphrase = cache.get(keyId);
        if (passphrase == null || !passphrase.isValid()) {
            passphrase = provider.getPassphraseFor(keyId);
            if (passphrase != null) {
                cache.put(keyId, passphrase);
            }
        }
        return passphrase;
    }

    @Override
    public PBESecretKeyDecryptor getDecryptor(Long keyId) {
        return protector.getDecryptor(keyId);
    }

    @Override
    public PBESecretKeyEncryptor getEncryptor(Long keyId) throws PGPException {
        return protector.getEncryptor(keyId);
    }
}
