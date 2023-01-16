// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.jetbrains.annotations.Nullable;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.info.KeyInfo;
import org.pgpainless.key.protection.CachingSecretKeyRingProtector;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.Passphrase;

/**
 * Implementation of the {@link SecretKeyRingProtector} which can be handed passphrases and keys separately,
 * and which then matches up passphrases and keys when needed.
 */
public class MatchMakingSecretKeyRingProtector implements SecretKeyRingProtector {

    private final Set<Passphrase> passphrases = new HashSet<>();
    private final Set<PGPSecretKeyRing> keys = new HashSet<>();
    private final CachingSecretKeyRingProtector protector = new CachingSecretKeyRingProtector();

    /**
     * Add a single passphrase to the protector.
     *
     * @param passphrase passphrase
     */
    public void addPassphrase(Passphrase passphrase) {
        if (passphrase.isEmpty()) {
            return;
        }

        if (!passphrases.add(passphrase)) {
            return;
        }

        for (PGPSecretKeyRing key : keys) {
            for (PGPSecretKey subkey : key) {
                if (protector.hasPassphrase(subkey.getKeyID())) {
                    continue;
                }

                testPassphrase(passphrase, subkey);
            }
        }
    }

    /**
     * Add a single {@link PGPSecretKeyRing} to the protector.
     *
     * @param key secret keys
     */
    public void addSecretKey(PGPSecretKeyRing key) {
        if (!keys.add(key)) {
            return;
        }

        for (PGPSecretKey subkey : key) {
            if (KeyInfo.isDecrypted(subkey)) {
                protector.addPassphrase(subkey.getKeyID(), Passphrase.emptyPassphrase());
            } else {
                for (Passphrase passphrase : passphrases) {
                    testPassphrase(passphrase, subkey);
                }
            }
        }
    }

    private void testPassphrase(Passphrase passphrase, PGPSecretKey subkey) {
        try {
            PBESecretKeyDecryptor decryptor = ImplementationFactory.getInstance().getPBESecretKeyDecryptor(passphrase);
            UnlockSecretKey.unlockSecretKey(subkey, decryptor);
            protector.addPassphrase(subkey.getKeyID(), passphrase);
        } catch (PGPException e) {
            // wrong password
        }
    }

    @Override
    public boolean hasPassphraseFor(Long keyId) {
        return protector.hasPassphrase(keyId);
    }

    @Nullable
    @Override
    public PBESecretKeyDecryptor getDecryptor(Long keyId) throws PGPException {
        return protector.getDecryptor(keyId);
    }

    @Nullable
    @Override
    public PBESecretKeyEncryptor getEncryptor(Long keyId) throws PGPException {
        return protector.getEncryptor(keyId);
    }

    /**
     * Clear all known passphrases from the protector.
     */
    public void clear() {
        for (Passphrase passphrase : passphrases) {
            passphrase.clear();
        }

        for (PGPSecretKeyRing key : keys) {
            protector.forgetPassphrase(key);
        }
    }
}
