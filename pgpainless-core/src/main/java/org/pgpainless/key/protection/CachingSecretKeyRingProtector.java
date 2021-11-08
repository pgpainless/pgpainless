// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider;
import org.pgpainless.util.Passphrase;

/**
 * Implementation of the {@link SecretKeyRingProtector} which holds a map of key ids and their passwords.
 * In case the needed passphrase is not contained in the map, the {@code missingPassphraseCallback} will be consulted,
 * and the passphrase is added to the map.
 */
public class CachingSecretKeyRingProtector implements SecretKeyRingProtector, SecretKeyPassphraseProvider {

    private final Map<Long, Passphrase> cache = new HashMap<>();
    private final SecretKeyRingProtector protector;
    private final SecretKeyPassphraseProvider provider;

    public CachingSecretKeyRingProtector() {
        this(null);
    }

    public CachingSecretKeyRingProtector(@Nullable SecretKeyPassphraseProvider missingPassphraseCallback) {
        this(
                new HashMap<>(),
                KeyRingProtectionSettings.secureDefaultSettings(),
                missingPassphraseCallback
        );
    }

    public CachingSecretKeyRingProtector(@Nonnull Map<Long, Passphrase> passphrases,
                                         @Nonnull KeyRingProtectionSettings protectionSettings,
                                         @Nullable SecretKeyPassphraseProvider missingPassphraseCallback) {
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
    public void addPassphrase(@Nonnull Long keyId, @Nonnull Passphrase passphrase) {
        this.cache.put(keyId, passphrase);
    }

    /**
     * Remember the given passphrase for all keys in the given key ring.
     *
     * @param keyRing key ring
     * @param passphrase passphrase
     */
    public void addPassphrase(@Nonnull PGPKeyRing keyRing, @Nonnull Passphrase passphrase) {
        Iterator<PGPPublicKey> keys = keyRing.getPublicKeys();
        while (keys.hasNext()) {
            PGPPublicKey publicKey = keys.next();
            addPassphrase(publicKey, passphrase);
        }
    }

    /**
     * Remember the given passphrase for the given (sub-)key.
     *
     * @param key key
     * @param passphrase passphrase
     */
    public void addPassphrase(@Nonnull PGPPublicKey key, @Nonnull Passphrase passphrase) {
        addPassphrase(key.getKeyID(), passphrase);
    }

    public void addPassphrase(@Nonnull OpenPgpFingerprint fingerprint, @Nonnull Passphrase passphrase) {
        addPassphrase(fingerprint.getKeyId(), passphrase);
    }

    /**
     * Remove a passphrase from the cache.
     * The passphrase will be cleared and then removed.
     *
     * @param keyId id of the key
     */
    public void forgetPassphrase(@Nonnull Long keyId) {
        Passphrase passphrase = cache.remove(keyId);
        if (passphrase != null) {
            passphrase.clear();
        }
    }

    /**
     * Forget the passphrase to all keys in the provided key ring.
     *
     * @param keyRing key ring
     */
    public void forgetPassphrase(@Nonnull PGPKeyRing keyRing) {
        Iterator<PGPPublicKey> keys = keyRing.getPublicKeys();
        while (keys.hasNext()) {
            PGPPublicKey publicKey = keys.next();
            forgetPassphrase(publicKey);
        }
    }

    /**
     * Forget the passphrase of the given public key.
     *
     * @param key key
     */
    public void forgetPassphrase(@Nonnull PGPPublicKey key) {
        forgetPassphrase(key.getKeyID());
    }

    @Override
    @Nullable
    public Passphrase getPassphraseFor(Long keyId) {
        Passphrase passphrase = cache.get(keyId);
        if (passphrase == null || !passphrase.isValid()) {
            if (provider == null) {
                return null;
            }
            passphrase = provider.getPassphraseFor(keyId);
            if (passphrase != null) {
                cache.put(keyId, passphrase);
            }
        }
        return passphrase;
    }

    @Override
    public boolean hasPassphrase(Long keyId) {
        Passphrase passphrase = cache.get(keyId);
        return passphrase != null && passphrase.isValid();
    }

    @Override
    public boolean hasPassphraseFor(Long keyId) {
        return hasPassphrase(keyId);
    }

    @Override
    @Nullable
    public PBESecretKeyDecryptor getDecryptor(@Nonnull Long keyId) throws PGPException {
        return protector.getDecryptor(keyId);
    }

    @Override
    @Nullable
    public PBESecretKeyEncryptor getEncryptor(@Nonnull Long keyId) throws PGPException {
        return protector.getEncryptor(keyId);
    }
}
