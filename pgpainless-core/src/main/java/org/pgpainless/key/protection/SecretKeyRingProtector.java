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
import java.util.concurrent.ConcurrentHashMap;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider;
import org.pgpainless.util.Passphrase;

/**
 * Task of the {@link SecretKeyRingProtector} is to map encryptor/decryptor objects to key-ids.
 * {@link PBESecretKeyEncryptor PBESecretKeyEncryptors}/{@link PBESecretKeyDecryptor PBESecretKeyDecryptors} are used
 * to encrypt/decrypt secret keys using a passphrase.
 *
 * While it is easy to create an implementation of this interface that fits your needs, there are a bunch of
 * implementations ready for use.
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
     * Return a protector for secret keys.
     * The protector maintains an in-memory cache of passphrases and can be extended with new passphrases
     * at runtime.
     *
     * See {@link CachingSecretKeyRingProtector} for how to memorize/forget additional passphrases during runtime.
     *
     * @param missingPassphraseCallback callback that is used to provide missing passphrases.
     * @return caching secret key protector
     */
    static CachingSecretKeyRingProtector defaultSecretKeyRingProtector(SecretKeyPassphraseProvider missingPassphraseCallback) {
        return new CachingSecretKeyRingProtector(
                new HashMap<>(),
                KeyRingProtectionSettings.secureDefaultSettings(),
                missingPassphraseCallback);
    }

    /**
     * Use the provided passphrase to lock/unlock all subkeys in the provided key ring.
     *
     * This protector will use the provided passphrase to lock/unlock all subkeys present in the provided keys object.
     * For other keys that are not present in the ring, it will return null.
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
     * This protector will only return a non-null encryptor/decryptor based on the provided passphrase if
     * {@link #getEncryptor(Long)}/{@link #getDecryptor(Long)} is getting called with the key-id of the provided key.
     *
     * Otherwise this protector will always return null.
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
     * This protector returns null for all {@link #getEncryptor(Long)}/{@link #getDecryptor(Long)} calls,
     * no matter what the key-id is.
     *
     * As a consequence, this protector can only "unlock" keys which are not protected using a passphrase, and it will
     * leave keys unprotected, should it be used to "protect" a key
     * (eg. in {@link org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditor#changePassphraseFromOldPassphrase(Passphrase)}).
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
        return new CachingSecretKeyRingProtector(passphraseMap, KeyRingProtectionSettings.secureDefaultSettings(), null);
    }
}
