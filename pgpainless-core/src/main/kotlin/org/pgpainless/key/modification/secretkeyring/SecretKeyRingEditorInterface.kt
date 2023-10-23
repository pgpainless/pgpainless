// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification.secretkeyring

import java.io.IOException
import java.security.InvalidAlgorithmParameterException
import java.security.NoSuchAlgorithmException
import java.util.*
import org.bouncycastle.openpgp.*
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.generation.KeySpec
import org.pgpainless.key.protection.KeyRingProtectionSettings
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.key.util.RevocationAttributes
import org.pgpainless.signature.subpackets.RevocationSignatureSubpackets
import org.pgpainless.signature.subpackets.SelfSignatureSubpackets
import org.pgpainless.util.Passphrase
import org.pgpainless.util.selection.userid.SelectUserId

interface SecretKeyRingEditorInterface {

    /**
     * Editors reference time. This time is used as creation date for new signatures, or as
     * reference when evaluating expiration of existing signatures.
     */
    val referenceTime: Date

    /**
     * Add a user-id to the key ring.
     *
     * @param userId user-id
     * @param protector protector to unlock the secret key
     * @return the builder
     * @throws PGPException in case we cannot generate a signature for the user-id
     */
    @Throws(PGPException::class)
    fun addUserId(userId: CharSequence, protector: SecretKeyRingProtector) =
        addUserId(userId, null, protector)

    /**
     * Add a user-id to the key ring.
     *
     * @param userId user-id
     * @param callback callback to modify the self-signature subpackets
     * @param protector protector to unlock the secret key
     * @return the builder
     * @throws PGPException in case we cannot generate a signature for the user-id
     */
    @Throws(PGPException::class)
    fun addUserId(
        userId: CharSequence,
        callback: SelfSignatureSubpackets.Callback? = null,
        protector: SecretKeyRingProtector
    ): SecretKeyRingEditorInterface

    /**
     * Add a user-id to the key ring and mark it as primary. If the user-id is already present, a
     * new certification signature will be created.
     *
     * @param userId user id
     * @param protector protector to unlock the secret key
     * @return the builder
     * @throws PGPException in case we cannot generate a signature for the user-id
     */
    @Throws(PGPException::class)
    fun addPrimaryUserId(
        userId: CharSequence,
        protector: SecretKeyRingProtector
    ): SecretKeyRingEditorInterface

    /**
     * Convenience method to revoke selected user-ids using soft revocation signatures. The
     * revocation will use [RevocationAttributes.Reason.USER_ID_NO_LONGER_VALID], so that the
     * user-id can be re-certified at a later point.
     *
     * @param selector selector to select user-ids
     * @param protector protector to unlock the primary key
     * @return the builder
     * @throws PGPException in case we cannot generate a revocation signature for the user-id
     */
    @Deprecated(
        "Use of SelectUserId class is deprecated.",
        ReplaceWith("removeUserId(protector, predicate)"))
    @Throws(PGPException::class)
    fun removeUserId(selector: SelectUserId, protector: SecretKeyRingProtector) =
        removeUserId(protector, selector)

    /**
     * Convenience method to revoke selected user-ids using soft revocation signatures. The
     * revocation will use [RevocationAttributes.Reason.USER_ID_NO_LONGER_VALID], so that the
     * user-id can be re-certified at a later point.
     *
     * @param protector protector to unlock the primary key
     * @param predicate predicate to select user-ids for revocation
     * @return the builder
     * @throws PGPException in case we cannot generate a revocation signature for the user-id
     */
    @Throws(PGPException::class)
    fun removeUserId(
        protector: SecretKeyRingProtector,
        predicate: (String) -> Boolean
    ): SecretKeyRingEditorInterface

    /**
     * Convenience method to revoke a single user-id using a soft revocation signature. The
     * revocation will use [RevocationAttributes.Reason.USER_ID_NO_LONGER_VALID] so that the user-id
     * can be re-certified at a later point.
     *
     * @param userId user-id to revoke
     * @param protector protector to unlock the primary key
     * @return the builder
     * @throws PGPException in case we cannot generate a revocation signature for the user-id
     */
    @Throws(PGPException::class)
    fun removeUserId(
        userId: CharSequence,
        protector: SecretKeyRingProtector
    ): SecretKeyRingEditorInterface

    /**
     * Replace a user-id on the key with a new one. The old user-id gets soft revoked and the new
     * user-id gets bound with the same signature subpackets as the old one, with one exception: If
     * the old user-id was implicitly primary (did not carry a
     * [org.bouncycastle.bcpg.sig.PrimaryUserID] packet, but effectively was primary), then the new
     * user-id will be explicitly marked as primary.
     *
     * @param oldUserId old user-id
     * @param newUserId new user-id
     * @param protector protector to unlock the secret key
     * @return the builder
     * @throws PGPException in case we cannot generate a revocation and certification signature
     * @throws java.util.NoSuchElementException if the old user-id was not found on the key; or if
     *   the oldUserId was already invalid
     */
    @Throws(PGPException::class)
    fun replaceUserId(
        oldUserId: CharSequence,
        newUserId: CharSequence,
        protector: SecretKeyRingProtector
    ): SecretKeyRingEditorInterface

    /**
     * Add a subkey to the key ring. The subkey will be generated from the provided [KeySpec].
     *
     * @param keySpec key specification
     * @param subkeyPassphrase passphrase to encrypt the sub key
     * @param callback callback to modify the subpackets of the subkey binding signature
     * @param protector protector to unlock the secret key of the key ring
     * @return the builder
     * @throws InvalidAlgorithmParameterException in case the user wants to use invalid parameters
     *   for the key
     * @throws NoSuchAlgorithmException in case of missing algorithm support in the crypto backend
     * @throws PGPException in case we cannot generate a binding signature for the subkey
     * @throws IOException in case of an IO error
     */
    @Throws(
        PGPException::class,
        IOException::class,
        InvalidAlgorithmParameterException::class,
        NoSuchAlgorithmException::class)
    fun addSubKey(
        keySpec: KeySpec,
        subkeyPassphrase: Passphrase,
        callback: SelfSignatureSubpackets.Callback? = null,
        protector: SecretKeyRingProtector
    ): SecretKeyRingEditorInterface

    /**
     * Add a subkey to the key ring.
     *
     * @param subkey subkey key pair
     * @param callback callback to modify the subpackets of the subkey binding signature
     * @param subkeyProtector protector to unlock and encrypt the subkey
     * @param primaryKeyProtector protector to unlock the primary key
     * @param keyFlag first mandatory key flag for the subkey
     * @param keyFlags optional additional key flags
     * @return builder
     * @throws PGPException in case we cannot generate a binding signature for the subkey
     * @throws IOException in case of an IO error
     */
    @Throws(PGPException::class, IOException::class)
    fun addSubKey(
        subkey: PGPKeyPair,
        callback: SelfSignatureSubpackets.Callback?,
        subkeyProtector: SecretKeyRingProtector,
        primaryKeyProtector: SecretKeyRingProtector,
        keyFlag: KeyFlag,
        vararg keyFlags: KeyFlag
    ): SecretKeyRingEditorInterface

    /**
     * Revoke the key ring using a hard revocation.
     *
     * @param protector protector of the primary key
     * @return the builder
     * @throws PGPException in case we cannot generate a revocation signature
     */
    @Throws(PGPException::class)
    fun revoke(protector: SecretKeyRingProtector) = revoke(protector, null as RevocationAttributes?)

    /**
     * Revoke the key ring using the provided revocation attributes. The attributes define, whether
     * the revocation was a hard revocation or not.
     *
     * @param protector protector of the primary key
     * @param revocationAttributes reason for the revocation
     * @return the builder
     * @throws PGPException in case we cannot generate a revocation signature
     */
    @Throws(PGPException::class)
    fun revoke(
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes? = null
    ): SecretKeyRingEditorInterface

    /**
     * Revoke the key ring. You can use the [RevocationSignatureSubpackets.Callback] to modify the
     * revocation signatures subpackets, e.g. in order to define whether this is a hard or soft
     * revocation.
     *
     * @param protector protector to unlock the primary secret key
     * @param callback callback to modify the revocations subpackets
     * @return builder
     * @throws PGPException in case we cannot generate a revocation signature
     */
    @Throws(PGPException::class)
    fun revoke(
        protector: SecretKeyRingProtector,
        callback: RevocationSignatureSubpackets.Callback?
    ): SecretKeyRingEditorInterface

    /**
     * Revoke the subkey binding signature of a subkey. The subkey with the provided fingerprint
     * will be revoked. If no suitable subkey is found, a [NoSuchElementException] will be thrown.
     *
     * @param fingerprint fingerprint of the subkey to be revoked
     * @param protector protector to unlock the primary key
     * @return the builder
     * @throws PGPException in case we cannot generate a revocation signature for the subkey
     */
    @Throws(PGPException::class)
    fun revokeSubKey(fingerprint: OpenPgpFingerprint, protector: SecretKeyRingProtector) =
        revokeSubKey(fingerprint, protector, null)

    /**
     * Revoke the subkey binding signature of a subkey. The subkey with the provided fingerprint
     * will be revoked. If no suitable subkey is found, a [NoSuchElementException] will be thrown.
     *
     * @param fingerprint fingerprint of the subkey to be revoked
     * @param protector protector to unlock the primary key
     * @param revocationAttributes reason for the revocation
     * @return the builder
     * @throws PGPException in case we cannot generate a revocation signature for the subkey
     */
    @Throws(PGPException::class)
    fun revokeSubKey(
        fingerprint: OpenPgpFingerprint,
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes? = null
    ): SecretKeyRingEditorInterface =
        revokeSubKey(fingerprint.keyId, protector, revocationAttributes)

    /**
     * Revoke the subkey binding signature of a subkey. The subkey with the provided key-id will be
     * revoked. If no suitable subkey is found, a [NoSuchElementException] will be thrown.
     *
     * @param subkeyId id of the subkey
     * @param protector protector to unlock the primary key
     * @return the builder
     * @throws PGPException in case we cannot generate a revocation signature for the subkey
     */
    @Throws(PGPException::class)
    fun revokeSubKey(subkeyId: Long, protector: SecretKeyRingProtector) =
        revokeSubKey(subkeyId, protector, null as RevocationAttributes?)

    /**
     * Revoke the subkey binding signature of a subkey. The subkey with the provided key-id will be
     * revoked. If no suitable subkey is found, a [NoSuchElementException] will be thrown.
     *
     * @param subkeyId id of the subkey
     * @param protector protector to unlock the primary key
     * @param revocationAttributes reason for the revocation
     * @return the builder
     * @throws PGPException in case we cannot generate a revocation signature for the subkey
     */
    @Throws(PGPException::class)
    fun revokeSubKey(
        subkeyId: Long,
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes? = null
    ): SecretKeyRingEditorInterface

    /**
     * Revoke the subkey binding signature of a subkey. The subkey with the provided key-id will be
     * revoked. If no suitable subkey is found, a [NoSuchElementException] will be thrown.
     *
     * The provided subpackets callback is used to modify the revocation signatures subpackets.
     *
     * @param subkeyId id of the subkey
     * @param protector protector to unlock the secret key ring
     * @param callback callback which can be used to modify the subpackets of the revocation
     *   signature
     * @return the builder
     * @throws PGPException in case we cannot generate a revocation signature for the subkey
     */
    @Throws(PGPException::class)
    fun revokeSubKey(
        subkeyId: Long,
        protector: SecretKeyRingProtector,
        callback: RevocationSignatureSubpackets.Callback?
    ): SecretKeyRingEditorInterface

    /**
     * Hard-revoke the given userID.
     *
     * @param userId userId to revoke
     * @param protector protector to unlock the primary key
     * @return the builder
     * @throws PGPException in case we cannot generate a revocation signature for the user-id
     */
    @Throws(PGPException::class)
    fun revokeUserId(userId: CharSequence, protector: SecretKeyRingProtector) =
        revokeUserId(userId, protector, null as RevocationAttributes?)

    /**
     * Revoke the given userID using the provided revocation attributes.
     *
     * @param userId userId to revoke
     * @param protector protector to unlock the primary key
     * @param revocationAttributes reason for the revocation
     * @return the builder
     * @throws PGPException in case we cannot generate a revocation signature for the user-id
     */
    @Throws(PGPException::class)
    fun revokeUserId(
        userId: CharSequence,
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes? = null
    ): SecretKeyRingEditorInterface

    /**
     * Revoke the provided user-id. Note: If you don't provide a
     * [RevocationSignatureSubpackets.Callback] which sets a revocation reason
     * ([RevocationAttributes]), the revocation will be considered hard. So if you intend to
     * re-certify the user-id at a later point to make it valid again, make sure to set a soft
     * revocation reason in the signatures hashed area using the subpacket callback.
     *
     * @param userId userid to be revoked
     * @param protector protector to unlock the primary secret key
     * @param callback callback to modify the revocations subpackets
     * @return builder
     * @throws PGPException in case we cannot generate a revocation signature for the user-id
     */
    @Throws(PGPException::class)
    fun revokeUserId(
        userId: CharSequence,
        protector: SecretKeyRingProtector,
        callback: RevocationSignatureSubpackets.Callback?
    ): SecretKeyRingEditorInterface

    /**
     * Revoke all user-ids that match the provided [SelectUserId] filter. The provided
     * [RevocationAttributes] will be set as reason for revocation in each revocation signature.
     *
     * Note: If you intend to re-certify these user-ids at a later point, make sure to choose a soft
     * revocation reason. See [RevocationAttributes.Reason] for more information.
     *
     * @param selector user-id selector
     * @param protector protector to unlock the primary secret key
     * @param revocationAttributes revocation attributes
     * @return builder
     * @throws PGPException in case we cannot generate a revocation signature for the user-id
     */
    @Throws(PGPException::class)
    @Deprecated(
        "Use of SelectUserId class is deprecated.",
        ReplaceWith("revokeUserIds(protector, revocationAttributes, predicate)"))
    fun revokeUserIds(
        selector: SelectUserId,
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes?
    ) = revokeUserIds(protector, revocationAttributes, selector)

    /**
     * Revoke all user-ids that match the provided [SelectUserId] filter. The provided
     * [RevocationAttributes] will be set as reason for revocation in each revocation signature.
     *
     * Note: If you intend to re-certify these user-ids at a later point, make sure to choose a soft
     * revocation reason. See [RevocationAttributes.Reason] for more information.
     *
     * @param protector protector to unlock the primary secret key
     * @param revocationAttributes revocation attributes
     * @param predicate to select user-ids for revocation
     * @return builder
     * @throws PGPException in case we cannot generate a revocation signature for the user-id
     */
    @Throws(PGPException::class)
    fun revokeUserIds(
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes?,
        predicate: (String) -> Boolean
    ): SecretKeyRingEditorInterface

    /**
     * Revoke all user-ids that match the provided [SelectUserId] filter. The provided
     * [RevocationSignatureSubpackets.Callback] will be used to modify the revocation signatures
     * subpackets.
     *
     * Note: If you intend to re-certify these user-ids at a later point, make sure to set a soft
     * revocation reason in the revocation signatures hashed subpacket area using the callback.
     *
     * See [RevocationAttributes.Reason] for more information.
     *
     * @param selector user-id selector
     * @param protector protector to unlock the primary secret key
     * @param callback callback to modify the revocations subpackets
     * @return builder
     * @throws PGPException in case we cannot generate a revocation signature for the user-id
     */
    @Throws(PGPException::class)
    @Deprecated(
        "Use of SelectUserId class is deprecated.",
        ReplaceWith("revokeUserIds(protector, callback, predicate)"))
    fun revokeUserIds(
        selector: SelectUserId,
        protector: SecretKeyRingProtector,
        callback: RevocationSignatureSubpackets.Callback?
    ) = revokeUserIds(protector, callback, selector)

    /**
     * Revoke all user-ids that match the provided [SelectUserId] filter. The provided
     * [RevocationSignatureSubpackets.Callback] will be used to modify the revocation signatures
     * subpackets.
     *
     * Note: If you intend to re-certify these user-ids at a later point, make sure to set a soft
     * revocation reason in the revocation signatures hashed subpacket area using the callback.
     *
     * See [RevocationAttributes.Reason] for more information.
     *
     * @param protector protector to unlock the primary secret key
     * @param callback callback to modify the revocations subpackets
     * @param predicate to select user-ids for revocation
     * @return builder
     * @throws PGPException in case we cannot generate a revocation signature for the user-id
     */
    @Throws(PGPException::class)
    fun revokeUserIds(
        protector: SecretKeyRingProtector,
        callback: RevocationSignatureSubpackets.Callback?,
        predicate: (String) -> Boolean
    ): SecretKeyRingEditorInterface

    /**
     * Set the expiration date for the primary key of the key ring. If the key is supposed to never
     * expire, then an expiration date of null is expected.
     *
     * @param expiration new expiration date or null
     * @param protector to unlock the secret key
     * @return the builder
     * @throws PGPException in case we cannot generate a new self-signature with the changed
     *   expiration date
     */
    @Throws(PGPException::class)
    fun setExpirationDate(
        expiration: Date?,
        protector: SecretKeyRingProtector
    ): SecretKeyRingEditorInterface

    /**
     * Create a minimal, self-authorizing revocation certificate, containing only the primary key
     * and a revocation signature. This type of revocation certificates was introduced in OpenPGP
     * v6. This method has no side effects on the original key and will leave it intact.
     *
     * @param protector protector to unlock the primary key.
     * @param revocationAttributes reason for the revocation (key revocation)
     * @return minimal revocation certificate
     * @throws PGPException in case we cannot generate a revocation signature
     */
    @Throws(PGPException::class)
    fun createMinimalRevocationCertificate(
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes?
    ): PGPPublicKeyRing

    /**
     * Create a detached revocation certificate, which can be used to revoke the whole key. The
     * original key will not be modified by this method.
     *
     * @param protector protector to unlock the primary key.
     * @param revocationAttributes reason for the revocation
     * @return revocation certificate
     * @throws PGPException in case we cannot generate a revocation certificate
     */
    @Throws(PGPException::class)
    fun createRevocation(
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes?
    ): PGPSignature

    /**
     * Create a detached revocation certificate, which can be used to revoke the specified subkey.
     * The original key will not be modified by this method.
     *
     * @param subkeyId id of the subkey to be revoked
     * @param protector protector to unlock the primary key.
     * @param revocationAttributes reason for the revocation
     * @return revocation certificate
     * @throws PGPException in case we cannot generate a revocation certificate
     */
    @Throws(PGPException::class)
    fun createRevocation(
        subkeyId: Long,
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes?
    ): PGPSignature

    /**
     * Create a detached revocation certificate, which can be used to revoke the specified subkey.
     * The original key will not be modified by this method.
     *
     * @param subkeyId id of the subkey to be revoked
     * @param protector protector to unlock the primary key.
     * @param callback callback to modify the subpackets of the revocation certificate.
     * @return revocation certificate
     * @throws PGPException in case we cannot generate a revocation certificate
     */
    @Throws(PGPException::class)
    fun createRevocation(
        subkeyId: Long,
        protector: SecretKeyRingProtector,
        callback: RevocationSignatureSubpackets.Callback?
    ): PGPSignature

    /**
     * Create a detached revocation certificate, which can be used to revoke the specified subkey.
     * The original key will not be modified by this method.
     *
     * @param subkeyFingerprint fingerprint of the subkey to be revoked
     * @param protector protector to unlock the primary key.
     * @param revocationAttributes reason for the revocation
     * @return revocation certificate
     * @throws PGPException in case we cannot generate a revocation certificate
     */
    @Throws(PGPException::class)
    fun createRevocation(
        subkeyFingerprint: OpenPgpFingerprint,
        protector: SecretKeyRingProtector,
        revocationAttributes: RevocationAttributes?
    ): PGPSignature

    /**
     * Change the passphrase of the whole key ring.
     *
     * @param oldPassphrase old passphrase (empty, if the key was unprotected)
     * @return next builder step
     */
    fun changePassphraseFromOldPassphrase(oldPassphrase: Passphrase) =
        changePassphraseFromOldPassphrase(
            oldPassphrase, KeyRingProtectionSettings.secureDefaultSettings())

    /**
     * Change the passphrase of the whole key ring.
     *
     * @param oldPassphrase old passphrase (empty, if the key was unprotected)
     * @param oldProtectionSettings custom settings for the old passphrase
     * @return next builder step
     */
    fun changePassphraseFromOldPassphrase(
        oldPassphrase: Passphrase,
        oldProtectionSettings: KeyRingProtectionSettings =
            KeyRingProtectionSettings.secureDefaultSettings()
    ): WithKeyRingEncryptionSettings

    /**
     * Change the passphrase of a single subkey in the key ring.
     *
     * Note: While it is a valid use-case to have different passphrases per subKey, this is one of
     * the reasons why OpenPGP sucks in practice.
     *
     * @param keyId id of the subkey
     * @param oldPassphrase old passphrase (empty if the key was unprotected)
     * @return next builder step
     */
    fun changeSubKeyPassphraseFromOldPassphrase(keyId: Long, oldPassphrase: Passphrase) =
        changeSubKeyPassphraseFromOldPassphrase(
            keyId, oldPassphrase, KeyRingProtectionSettings.secureDefaultSettings())

    /**
     * Change the passphrase of a single subkey in the key ring.
     *
     * Note: While it is a valid use-case to have different passphrases per subKey, this is one of
     * the reasons why OpenPGP sucks in practice.
     *
     * @param keyId id of the subkey
     * @param oldPassphrase old passphrase (empty if the key was unprotected)
     * @param oldProtectionSettings custom settings for the old passphrase
     * @return next builder step
     */
    fun changeSubKeyPassphraseFromOldPassphrase(
        keyId: Long,
        oldPassphrase: Passphrase,
        oldProtectionSettings: KeyRingProtectionSettings
    ): WithKeyRingEncryptionSettings

    interface WithKeyRingEncryptionSettings {

        /**
         * Set secure default settings for the symmetric passphrase encryption. Note that this
         * obviously has no effect if you decide to set [WithPassphrase.toNoPassphrase].
         *
         * @return next builder step
         */
        fun withSecureDefaultSettings(): WithPassphrase

        /**
         * Set custom settings for the symmetric passphrase encryption.
         *
         * @param settings custom settings
         * @return next builder step
         */
        fun withCustomSettings(settings: KeyRingProtectionSettings): WithPassphrase
    }

    interface WithPassphrase {

        /**
         * Set the passphrase.
         *
         * @param passphrase passphrase
         * @return editor builder
         * @throws PGPException in case the passphrase cannot be changed
         */
        @Throws(PGPException::class)
        fun toNewPassphrase(passphrase: Passphrase): SecretKeyRingEditorInterface

        /**
         * Leave the key unprotected.
         *
         * @return editor builder
         * @throws PGPException in case the passphrase cannot be changed
         */
        @Throws(PGPException::class) fun toNoPassphrase(): SecretKeyRingEditorInterface
    }

    /**
     * Return the [PGPSecretKeyRing].
     *
     * @return the key
     */
    fun done(): PGPSecretKeyRing

    fun addSubKey(
        keySpec: KeySpec,
        subkeyPassphrase: Passphrase,
        protector: SecretKeyRingProtector
    ): SecretKeyRingEditorInterface
}
