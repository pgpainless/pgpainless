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

    /**
     * Use the provided passphrase to lock/unlock all subkeys in the provided key ring.
     *
     * @param passphrase passphrase
     * @param keys key ring
     * @return protector
     */
    static SecretKeyRingProtector unlockAllKeysWith(Passphrase passphrase, PGPSecretKeyRing keys) {
        Map<Long, Passphrase> map = new ConcurrentHashMap<>();
        for (PGPSecretKey secretKey : keys) {
            map.put(secretKey.getKeyID(), passphrase);
        }
        return fromPassphraseMap(map);
    }

    /**
     * Use the provided passphrase to lock/unlock only the provided (sub-)key.
     *
     * @param passphrase passphrase
     * @param key key to lock/unlock
     * @return protector
     */
    static SecretKeyRingProtector unlockSingleKeyWith(Passphrase passphrase, PGPSecretKey key) {
        return PasswordBasedSecretKeyRingProtector.forKey(key, passphrase);
    }

    /**
     * Protector for unprotected keys.
     *
     * @return protector
     */
    static SecretKeyRingProtector unprotectedKeys() {
        return new UnprotectedKeysProtector();
    }

    /**
     * Use the provided map of key-ids and passphrases to unlock keys.
     *
     * @param passphraseMap map of key ids and their respective passphrases
     * @return protector
     */
    static SecretKeyRingProtector fromPassphraseMap(Map<Long, Passphrase> passphraseMap) {
        return new PassphraseMapKeyRingProtector(passphraseMap, KeyRingProtectionSettings.secureDefaultSettings(), null);
    }
}
