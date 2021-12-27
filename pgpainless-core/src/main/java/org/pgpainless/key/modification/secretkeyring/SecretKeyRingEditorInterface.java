// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification.secretkeyring;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.OpenPgpFingerprint;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.protection.KeyRingProtectionSettings;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.signature.subpackets.RevocationSignatureSubpackets;
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.selection.userid.SelectUserId;

public interface SecretKeyRingEditorInterface {

    /**
     * Add a user-id to the key ring.
     *
     * @param userId user-id
     * @param secretKeyRingProtector protector to unlock the secret key
     * @return the builder
     */
    SecretKeyRingEditorInterface addUserId(
            @Nonnull CharSequence userId,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector)
            throws PGPException;

    /**
     * Add a user-id to the key ring.
     *
     * @param userId user-id
     * @param signatureSubpacketCallback callback that can be used to modify signature subpackets of the
     *                                   certification signature.
     * @param protector protector to unlock the primary secret key
     * @return the builder
     * @throws PGPException
     */
    SecretKeyRingEditorInterface addUserId(
            @Nonnull CharSequence userId,
            @Nullable SelfSignatureSubpackets.Callback signatureSubpacketCallback,
            @Nonnull SecretKeyRingProtector protector)
            throws PGPException;

    /**
     * Add a user-id to the key ring and mark it as primary.
     * If the user-id is already present, a new certification signature will be created.
     *
     * @param userId user id
     * @param protector protector to unlock the secret key
     * @return the builder
     */
    SecretKeyRingEditorInterface addPrimaryUserId(
            @Nonnull CharSequence userId,
            @Nonnull SecretKeyRingProtector protector)
            throws PGPException;

    SecretKeyRingEditorInterface removeUserId(SelectUserId userIdSelector,
                                              SecretKeyRingProtector protector)
        throws PGPException;

    SecretKeyRingEditorInterface removeUserId(CharSequence userId,
                                              SecretKeyRingProtector protector)
        throws PGPException;

    /**
     * Add a subkey to the key ring.
     * The subkey will be generated from the provided {@link KeySpec}.
     *
     * @param keySpec key specification
     * @param subKeyPassphrase passphrase to encrypt the sub key
     * @param secretKeyRingProtector protector to unlock the secret key of the key ring
     * @return the builder
     */
    SecretKeyRingEditorInterface addSubKey(
            @Nonnull KeySpec keySpec,
            @Nonnull Passphrase subKeyPassphrase,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException;

    /**
     * Add a subkey to the key ring.
     * The subkey will be generated from the provided {@link KeySpec}.
     *
     * @param keySpec key spec of the subkey
     * @param subkeyPassphrase passphrase to encrypt the subkey
     * @param subpacketsCallback callback to modify the subpackets of the subkey binding signature
     * @param secretKeyRingProtector protector to unlock the primary key
     * @return builder
     */
    SecretKeyRingEditorInterface addSubKey(
            @Nonnull KeySpec keySpec,
            @Nonnull Passphrase subkeyPassphrase,
            @Nullable SelfSignatureSubpackets.Callback subpacketsCallback,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector)
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException;

    /**
     * Add a subkey to the key ring.
     *
     * @param subkey subkey key pair
     * @param bindingSignatureCallback callback to modify the subpackets of the subkey binding signature
     * @param subkeyProtector protector to unlock and encrypt the subkey
     * @param primaryKeyProtector protector to unlock the primary key
     * @param keyFlag first key flag for the subkey
     * @param additionalKeyFlags optional additional key flags
     * @return builder
     */
    SecretKeyRingEditorInterface addSubKey(
            @Nonnull PGPKeyPair subkey,
            @Nullable SelfSignatureSubpackets.Callback bindingSignatureCallback,
            @Nonnull SecretKeyRingProtector subkeyProtector,
            @Nonnull SecretKeyRingProtector primaryKeyProtector,
            @Nonnull KeyFlag keyFlag,
            KeyFlag... additionalKeyFlags)
            throws PGPException, IOException, NoSuchAlgorithmException;

    /**
     * Revoke the key ring.
     * The revocation will be a hard revocation, rendering the whole key invalid for any past or future signatures.
     *
     * @param secretKeyRingProtector protector of the primary key
     * @return the builder
     */
    default SecretKeyRingEditorInterface revoke(
            @Nonnull SecretKeyRingProtector secretKeyRingProtector)
            throws PGPException {
        return revoke(secretKeyRingProtector, (RevocationAttributes) null);
    }

    /**
     * Revoke the key ring using the provided revocation attributes.
     * The attributes define, whether the revocation was a hard revocation or not.
     *
     * @param secretKeyRingProtector protector of the primary key
     * @param revocationAttributes reason for the revocation
     * @return the builder
     */
    SecretKeyRingEditorInterface revoke(
            @Nonnull SecretKeyRingProtector secretKeyRingProtector,
            @Nullable RevocationAttributes revocationAttributes)
            throws PGPException;

    /**
     * Revoke the key ring.
     * You can use the {@link RevocationSignatureSubpackets.Callback} to modify the revocation signatures
     * subpackets, eg. in order to define whether this is a hard or soft revocation.
     *
     * @param secretKeyRingProtector protector to unlock the primary secret key
     * @param subpacketsCallback callback to modify the revocations subpackets
     * @return builder
     */
    SecretKeyRingEditorInterface revoke(
            @Nonnull SecretKeyRingProtector secretKeyRingProtector,
            @Nullable RevocationSignatureSubpackets.Callback subpacketsCallback) throws PGPException;

    /**
     * Revoke the subkey binding signature of a subkey.
     * The subkey with the provided fingerprint will be revoked.
     * If no suitable subkey is found, a {@link java.util.NoSuchElementException} will be thrown.
     *
     * Note: This method will hard-revoke the provided subkey, meaning it cannot be re-certified at a later point.
     * If you instead want to temporarily "deactivate" the subkey, provide a soft revocation reason,
     * eg. by calling {@link #revokeSubKey(OpenPgpFingerprint, SecretKeyRingProtector, RevocationAttributes)}
     * and provide a suitable {@link RevocationAttributes} object.
     *
     * @param fingerprint fingerprint of the subkey to be revoked
     * @param secretKeyRingProtector protector to unlock the secret key ring
     * @return the builder
     */
    default SecretKeyRingEditorInterface revokeSubKey(
            @Nonnull OpenPgpFingerprint fingerprint,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector)
            throws PGPException {
        return revokeSubKey(fingerprint, secretKeyRingProtector, null);
    }

    /**
     * Revoke the subkey binding signature of a subkey.
     * The subkey with the provided fingerprint will be revoked.
     * If no suitable subkey is found, a {@link java.util.NoSuchElementException} will be thrown.
     *
     * @param fingerprint fingerprint of the subkey to be revoked
     * @param secretKeyRingProtector protector to unlock the primary key
     * @param revocationAttributes reason for the revocation
     * @return the builder
     */
    default SecretKeyRingEditorInterface revokeSubKey(
            OpenPgpFingerprint fingerprint,
            SecretKeyRingProtector secretKeyRingProtector,
            RevocationAttributes revocationAttributes)
            throws PGPException {
        return revokeSubKey(fingerprint.getKeyId(),
                secretKeyRingProtector,
                revocationAttributes);
    }

    /**
     * Revoke the subkey binding signature of a subkey.
     * The subkey with the provided key-id will be revoked.
     * If no suitable subkey is found, a {@link java.util.NoSuchElementException} will be thrown.
     *
     * @param subKeyId id of the subkey
     * @param secretKeyRingProtector protector to unlock the primary key
     * @param revocationAttributes reason for the revocation
     * @return the builder
     */
    SecretKeyRingEditorInterface revokeSubKey(
            long subKeyId,
            SecretKeyRingProtector secretKeyRingProtector,
            RevocationAttributes revocationAttributes)
            throws PGPException;

    /**
     * Revoke the subkey binding signature of a subkey.
     * The subkey with the provided key-id will be revoked.
     * If no suitable subkey is found, q {@link java.util.NoSuchElementException} will be thrown.
     *
     * Note: This method will hard-revoke the subkey, meaning it cannot be re-bound at a later point.
     * If you intend to re-bind the subkey in order to make it usable again at a later point in time,
     * consider using {@link #revokeSubKey(long, SecretKeyRingProtector, RevocationAttributes)}
     * and provide a soft revocation reason.
     *
     * @param subKeyId id of the subkey
     * @param secretKeyRingProtector protector to unlock the secret key ring
     * @return the builder
     */
    default SecretKeyRingEditorInterface revokeSubKey(
            long subKeyId,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector)
            throws PGPException {

        return revokeSubKey(
                subKeyId,
                secretKeyRingProtector,
                (RevocationSignatureSubpackets.Callback) null);
    }

    /**
     * Revoke the subkey binding signature of a subkey.
     * The subkey with the provided key-id will be revoked.
     * If no suitable subkey is found, q {@link java.util.NoSuchElementException} will be thrown.
     *
     * The provided subpackets callback is used to modify the revocation signatures subpackets.
     *
     * @param keyID id of the subkey
     * @param secretKeyRingProtector protector to unlock the secret key ring
     * @param subpacketsCallback callback which can be used to modify the subpackets of the revocation
     *                           signature
     * @return the builder
     */
    SecretKeyRingEditorInterface revokeSubKey(
            long keyID,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector,
            @Nullable RevocationSignatureSubpackets.Callback subpacketsCallback)
            throws PGPException;

    /**
     * Revoke the given userID.
     * The revocation will be a hard revocation, rendering the user-id invalid for any past or future signatures.
     * If you intend to re-certify the user-id at a later point in time, consider using
     * {@link #revokeUserId(CharSequence, SecretKeyRingProtector, RevocationAttributes)} instead and provide
     * a soft revocation reason.
     *
     * @param userId userId to revoke
     * @param secretKeyRingProtector protector to unlock the primary key
     * @return the builder
     */
    default SecretKeyRingEditorInterface revokeUserId(
            @Nonnull CharSequence userId,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector)
            throws PGPException {
        return revokeUserId(userId, secretKeyRingProtector, (RevocationAttributes) null);
    }

    /**
     * Revoke the given userID using the provided revocation attributes.
     *
     * @param userId userId to revoke
     * @param secretKeyRingProtector protector to unlock the primary key
     * @param revocationAttributes reason for the revocation
     * @return the builder
     */
    SecretKeyRingEditorInterface revokeUserId(
            @Nonnull CharSequence userId,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector,
            @Nullable RevocationAttributes revocationAttributes)
            throws PGPException;

    /**
     * Revoke the provided user-id.
     * Note: If you don't provide a {@link RevocationSignatureSubpackets.Callback} which
     * sets a revocation reason ({@link RevocationAttributes}), the revocation might be considered hard.
     * So if you intend to re-certify the user-id at a later point to make it valid again,
     * make sure to set a soft revocation reason in the signatures hashed area using the subpacket callback.
     *
     * @param userId userid to be revoked
     * @param secretKeyRingProtector protector to unlock the primary secret key
     * @param subpacketCallback callback to modify the revocations subpackets
     * @return builder
     */
    SecretKeyRingEditorInterface revokeUserId(
            @Nonnull CharSequence userId,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector,
            @Nullable RevocationSignatureSubpackets.Callback subpacketCallback)
            throws PGPException;

    /**
     * Revoke all user-ids that match the provided {@link SelectUserId} filter.
     * The provided {@link RevocationAttributes} will be set as reason for revocation in each
     * revocation signature.
     *
     * Note: If you intend to re-certify these user-ids at a later point, make sure to choose
     * a soft revocation reason. See {@link RevocationAttributes.Reason} for more information.
     *
     * @param userIdSelector user-id selector
     * @param secretKeyRingProtector protector to unlock the primary secret key
     * @param revocationAttributes revocation attributes
     * @return builder
     * @throws PGPException
     */
    SecretKeyRingEditorInterface revokeUserIds(
            @Nonnull SelectUserId userIdSelector,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector,
            @Nullable RevocationAttributes revocationAttributes)
            throws PGPException;

    /**
     * Revoke all user-ids that match the provided {@link SelectUserId} filter.
     * The provided {@link RevocationSignatureSubpackets.Callback} will be used to modify the
     * revocation signatures subpackets.
     *
     * Note: If you intend to re-certify these user-ids at a later point, make sure to set
     * a soft revocation reason in the revocation signatures hashed subpacket area using the callback.
     *
     * See {@link RevocationAttributes.Reason} for more information.
     *
     * @param userIdSelector user-id selector
     * @param secretKeyRingProtector protector to unlock the primary secret key
     * @param subpacketsCallback callback to modify the revocations subpackets
     * @return builder
     * @throws PGPException
     */
    SecretKeyRingEditorInterface revokeUserIds(
            @Nonnull SelectUserId userIdSelector,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector,
            @Nullable RevocationSignatureSubpackets.Callback subpacketsCallback)
            throws PGPException;

    /**
     * Set the expiration date for the primary key of the key ring.
     * If the key is supposed to never expire, then an expiration date of null is expected.
     *
     * @param expiration new expiration date or null
     * @param secretKeyRingProtector to unlock the secret key
     * @return the builder
     */
    SecretKeyRingEditorInterface setExpirationDate(
            @Nullable Date expiration,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector)
            throws PGPException;

    /**
     * Create a detached revocation certificate, which can be used to revoke the whole key.
     *
     * @param secretKeyRingProtector protector to unlock the primary key.
     * @param revocationAttributes reason for the revocation
     * @return revocation certificate
     */
    PGPSignature createRevocationCertificate(
            @Nonnull SecretKeyRingProtector secretKeyRingProtector,
            @Nullable RevocationAttributes revocationAttributes)
            throws PGPException;

    /**
     * Create a detached revocation certificate, which can be used to revoke the specified subkey.
     *
     * @param subkeyId id of the subkey to be revoked
     * @param secretKeyRingProtector protector to unlock the primary key.
     * @param revocationAttributes reason for the revocation
     * @return revocation certificate
     */
    PGPSignature createRevocationCertificate(
            long subkeyId,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector,
            @Nullable RevocationAttributes revocationAttributes)
            throws PGPException;

    /**
     * Create a detached revocation certificate, which can be used to revoke the specified subkey.
     *
     * @param subkeyId id of the subkey to be revoked
     * @param secretKeyRingProtector protector to unlock the primary key.
     * @param certificateSubpacketsCallback callback to modify the subpackets of the revocation certificate.
     * @return revocation certificate
     */
    PGPSignature createRevocationCertificate(
            long subkeyId,
            @Nonnull SecretKeyRingProtector secretKeyRingProtector,
            @Nullable RevocationSignatureSubpackets.Callback certificateSubpacketsCallback)
            throws PGPException;

    /**
     * Create a detached revocation certificate, which can be used to revoke the specified subkey.
     *
     * @param subkeyFingerprint fingerprint of the subkey to be revoked
     * @param secretKeyRingProtector protector to unlock the primary key.
     * @param revocationAttributes reason for the revocation
     * @return revocation certificate
     */
    default PGPSignature createRevocationCertificate(
            OpenPgpFingerprint subkeyFingerprint,
            SecretKeyRingProtector secretKeyRingProtector,
            @Nullable RevocationAttributes revocationAttributes)
            throws PGPException {

        return createRevocationCertificate(
                subkeyFingerprint.getKeyId(),
                secretKeyRingProtector,
                revocationAttributes);
    }

    /**
     * Change the passphrase of the whole key ring.
     *
     * @param oldPassphrase old passphrase or null, if the key was unprotected
     * @return next builder step
     */
    default WithKeyRingEncryptionSettings changePassphraseFromOldPassphrase(
            @Nullable Passphrase oldPassphrase) {
        return changePassphraseFromOldPassphrase(oldPassphrase, KeyRingProtectionSettings.secureDefaultSettings());
    }

    /**
     * Change the passphrase of the whole key ring.
     *
     * @param oldPassphrase old passphrase or null, if the key was unprotected
     * @param oldProtectionSettings custom settings for the old passphrase
     * @return next builder step
     */
    WithKeyRingEncryptionSettings changePassphraseFromOldPassphrase(
            @Nullable Passphrase oldPassphrase,
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
    default WithKeyRingEncryptionSettings changeSubKeyPassphraseFromOldPassphrase(
            @Nonnull Long keyId,
            @Nullable Passphrase oldPassphrase) {
        return changeSubKeyPassphraseFromOldPassphrase(keyId, oldPassphrase, KeyRingProtectionSettings.secureDefaultSettings());
    }

    WithKeyRingEncryptionSettings changeSubKeyPassphraseFromOldPassphrase(
            @Nonnull Long keyId,
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
        SecretKeyRingEditorInterface toNewPassphrase(Passphrase passphrase)
                throws PGPException;

        /**
         * Leave the key unprotected.
         *
         * @return editor builder
         */
        SecretKeyRingEditorInterface toNoPassphrase() throws PGPException;
    }

    /**
     * Return the {@link PGPSecretKeyRing}.
     * @return the key
     */
    PGPSecretKeyRing done();

}
