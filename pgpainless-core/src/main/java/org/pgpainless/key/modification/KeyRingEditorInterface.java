/*
 * Copyright 2020 Paul Schaub.
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
package org.pgpainless.key.modification;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.protection.KeyRingProtectionSettings;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;

public interface KeyRingEditorInterface {

    /**
     * Add a user-id to the primary key of the key ring.
     *
     * @param userId user-id
     * @return the builder
     */
    KeyRingEditorInterface addUserId(String userId, SecretKeyRingProtector secretKeyRingProtector) throws PGPException;

    default KeyRingEditorInterface addUserId(OpenPgpV4Fingerprint fingerprint, String userId, SecretKeyRingProtector secretKeyRingProtector) throws PGPException {
        return addUserId(fingerprint.getKeyId(), userId, secretKeyRingProtector);
    }

    KeyRingEditorInterface addUserId(long keyId, String userId, SecretKeyRingProtector secretKeyRingProtector) throws PGPException;

    /**
     * Remove a user-id from the primary key of the key ring.
     *
     * @param userId exact user-id to be removed
     * @return the builder
     */
    KeyRingEditorInterface deleteUserId(String userId, SecretKeyRingProtector secretKeyRingProtector);

    default KeyRingEditorInterface deleteUserId(OpenPgpV4Fingerprint fingerprint, String userId, SecretKeyRingProtector secretKeyRingProtector) {
        return deleteUserId(fingerprint.getKeyId(), userId, secretKeyRingProtector);
    }

    KeyRingEditorInterface deleteUserId(long keyId, String userId, SecretKeyRingProtector secretKeyRingProtector);

    /**
     * Add a subkey to the key ring.
     * The subkey will be generated from the provided {@link KeySpec}.
     *
     * @param keySpec key specification
     * @return the builder
     */
    KeyRingEditorInterface addSubKey(KeySpec keySpec, SecretKeyRingProtector secretKeyRingProtector);

    /**
     * Delete a subkey from the key ring.
     * The subkey with the provided fingerprint will be remove from the key ring.
     * If no suitable subkey is found, a {@link java.util.NoSuchElementException} will be thrown.
     *
     * @param fingerprint fingerprint of the subkey to be removed
     * @return the builder
     */
    KeyRingEditorInterface deleteSubKey(OpenPgpV4Fingerprint fingerprint, SecretKeyRingProtector secretKeyRingProtector);

    /**
     * Delete a subkey from the key ring.
     * The subkey with the provided key-id will be removed from the key ring.
     * If no suitable subkey is found, a {@link java.util.NoSuchElementException} will be thrown.
     *
     * @param subKeyId id of the subkey
     * @return the builder
     */
    KeyRingEditorInterface deleteSubKey(long subKeyId, SecretKeyRingProtector secretKeyRingProtector);

    /**
     * Revoke the subkey binding signature of a subkey.
     * The subkey with the provided fingerprint will be revoked.
     * If no suitable subkey is found, a {@link java.util.NoSuchElementException} will be thrown.
     *
     * @param fingerprint fingerprint of the subkey to be revoked
     * @return the builder
     */
    KeyRingEditorInterface revokeSubKey(OpenPgpV4Fingerprint fingerprint, SecretKeyRingProtector secretKeyRingProtector);

    /**
     * Revoke the subkey binding signature of a subkey.
     * The subkey with the provided key-id will be revoked.
     * If no suitable subkey is found, q {@link java.util.NoSuchElementException} will be thrown.
     *
     * @param subKeyId id of the subkey
     * @return the builder
     */
    KeyRingEditorInterface revokeSubKey(long subKeyId, SecretKeyRingProtector secretKeyRingProtector);

    /**
     * Change the passphrase of the whole key ring.
     *
     * @param oldPassphrase old passphrase or null, if the key was unprotected
     * @return next builder step
     */
    default WithKeyRingEncryptionSettings changePassphraseFromOldPassphrase(@Nullable Passphrase oldPassphrase) {
        return changePassphraseFromOldPassphrase(oldPassphrase, KeyRingProtectionSettings.secureDefaultSettings());
    }

    WithKeyRingEncryptionSettings changePassphraseFromOldPassphrase(@Nullable Passphrase oldPassphrase,
                                                                    @Nonnull KeyRingProtectionSettings oldProtectionSettings);

    /**
     * Change the passphrase of a single subkey in the key ring.
     *
     * Note: While it is a valid use-case to have different passphrases per subKey,
     *  this is one of the reasons why OpenPGP sucks in practice.
     *
     * @param keyId id of the subkey
     * @param oldPassphrase old passphrase
     * @return next builder step
     */
    default WithKeyRingEncryptionSettings changeSubKeyPassphraseFromOldPassphrase(@Nonnull Long keyId,
                                                                                  @Nullable Passphrase oldPassphrase) {
        return changeSubKeyPassphraseFromOldPassphrase(keyId, oldPassphrase, KeyRingProtectionSettings.secureDefaultSettings());
    }

    WithKeyRingEncryptionSettings changeSubKeyPassphraseFromOldPassphrase(@Nonnull Long keyId,
                                                                          @Nullable Passphrase oldPassphrase,
                                                                          @Nonnull KeyRingProtectionSettings oldProtectionSettings);

    interface WithKeyRingEncryptionSettings {

        /**
         * Set secure default settings for the symmetric passphrase encryption.
         * Note that this obviously has no effect if you decide to set {@link WithPassphrase#toNoPassphrase()}.
         *
         * @return next builder step
         */
        WithPassphrase withSecureDefaultSettings();

        /**
         * Set custom settings for the symmetric passphrase encryption.
         *
         * @param settings custom settings
         * @return next builder step
         */
        WithPassphrase withCustomSettings(KeyRingProtectionSettings settings);

    }

    interface WithPassphrase {

        /**
         * Set the passphrase.
         *
         * @param passphrase passphrase
         * @return editor builder
         */
        KeyRingEditorInterface toNewPassphrase(Passphrase passphrase) throws PGPException;

        /**
         * Leave the key unprotected.
         *
         * @return editor builder
         */
        KeyRingEditorInterface toNoPassphrase() throws PGPException;
    }

    /**
     * Return the {@link PGPSecretKeyRing}.
     * @return the key
     */
    PGPSecretKeyRing done();

}
