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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.pgpainless.util.Passphrase;

/**
 * Interface that is used to provide secret key ring encryptors and decryptors.
 *
 * @deprecated use {@link SecretKeyRingProtector2} instead.
 */
public interface SecretKeyRingProtector {

    /**
     * Return a decryptor for the key of id {@code keyId}.
     * This method returns null if the key is unprotected.
     *
     * @param keyId id of the key
     * @return decryptor for the key
     */
    @Nullable PBESecretKeyDecryptor getDecryptor(Long keyId) throws PGPException;

    /**
     * Return an encryptor for the key of id {@code keyId}.
     * This method returns null if the key is unprotected.
     *
     * @param keyId id of the key
     * @return encryptor for the key
     * @throws PGPException if the encryptor cannot be created for some reason
     */
    @Nullable PBESecretKeyEncryptor getEncryptor(Long keyId) throws PGPException;

    static SecretKeyRingProtector unlockAllKeysWith(Passphrase passphrase, PGPSecretKeyRing keys) {
        Map<Long, Passphrase> map = new ConcurrentHashMap<>();
        for (PGPSecretKey secretKey : keys) {
            map.put(secretKey.getKeyID(), passphrase);
        }
        return fromPassphraseMap(map);
    }

    static SecretKeyRingProtector unlockSingleKeyWith(Passphrase passphrase, PGPSecretKey key) {
        return PasswordBasedSecretKeyRingProtector.forKey(key, passphrase);
    }

    static SecretKeyRingProtector unprotectedKeys() {
        return new UnprotectedKeysProtector();
    }

    static SecretKeyRingProtector fromPassphraseMap(Map<Long, Passphrase> passphraseMap) {
        return new PassphraseMapKeyRingProtector(passphraseMap, KeyRingProtectionSettings.secureDefaultSettings(), null);
    }
}
