// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.info

import java.util.*
import kotlin.NoSuchElementException
import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPSecretKey
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.*
import org.pgpainless.bouncycastle.extensions.*
import org.pgpainless.exception.KeyException.UnboundUserIdException
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.SubkeyIdentifier
import org.pgpainless.key.util.KeyRingUtils
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil.Companion.getKeyExpirationTimeAsDate
import org.pgpainless.util.DateUtil
import org.slf4j.LoggerFactory

class KeyRingInfo(
    val keys: OpenPGPCertificate,
    private val api: PGPainless = PGPainless.getInstance(),
    private val referenceDate: Date = Date()
) {

    constructor(
        keys: PGPKeyRing,
        api: PGPainless = PGPainless.getInstance(),
        referenceDate: Date = Date()
    ) : this(
        if (keys is PGPSecretKeyRing) OpenPGPKey(keys, api.implementation)
        else OpenPGPCertificate(keys, api.implementation),
        api,
        referenceDate)

    @JvmOverloads
    constructor(
        keys: PGPKeyRing,
        referenceDate: Date = Date()
    ) : this(keys, PGPainless.getInstance(), referenceDate)

    /** Primary [OpenPGPCertificate.OpenPGPPrimaryKey]. */
    val primaryKey: OpenPGPCertificate.OpenPGPPrimaryKey = keys.primaryKey

    /** Primary [OpenPGPCertificate.OpenPGPPrimaryKey]. */
    @Deprecated("Use primaryKey instead.", replaceWith = ReplaceWith("primaryKey"))
    val publicKey: OpenPGPCertificate.OpenPGPPrimaryKey = primaryKey

    /** Primary key ID. */
    val keyIdentifier: KeyIdentifier = primaryKey.keyIdentifier

    @Deprecated(
        "Use of raw key-ids is deprecated in favor of key-identifiers",
        replaceWith = ReplaceWith("keyIdentifier"))
    val keyId: Long = keyIdentifier.keyId

    /** Primary key fingerprint. */
    val fingerprint: OpenPgpFingerprint = OpenPgpFingerprint.of(primaryKey.pgpPublicKey)

    /** All User-IDs (valid, expired, revoked). */
    val userIds: List<String> = KeyRingUtils.getUserIdsIgnoringInvalidUTF8(primaryKey.pgpPublicKey)

    /** Primary User-ID. */
    val primaryUserId: String? = keys.getPrimaryUserId(referenceDate)?.userId

    /** Revocation State. */
    val revocationState: RevocationState =
        primaryKey.getLatestSelfSignature(referenceDate)?.let {
            if (!it.isRevocation) RevocationState.notRevoked()
            else if (it.isHardRevocation) RevocationState.hardRevoked()
            else RevocationState.softRevoked(it.creationTime)
        }
            ?: RevocationState.notRevoked()
    /**
     * Return the date on which the primary key was revoked, or null if it has not yet been revoked.
     *
     * @return revocation date or null
     */
    val revocationDate: Date? =
        if (revocationState.isSoftRevocation()) revocationState.date else null

    /**
     * Primary [OpenPGPSecretKey] of this key ring or null if the key ring is not a [OpenPGPKey].
     */
    val secretKey: OpenPGPSecretKey? =
        if (keys.isSecretKey) {
            (keys as OpenPGPKey).primarySecretKey
        } else null

    /** OpenPGP key version. */
    val version: OpenPGPKeyVersion = keys.getKeyVersion()

    /**
     * Return all [public component keys][OpenPGPComponentKey] of this key ring. The first key in
     * the list being the primary key. Note that the list is unmodifiable.
     *
     * @return list of public keys
     */
    val publicKeys: List<OpenPGPComponentKey> = keys.keys

    /** All secret keys. If the key ring is not an [OpenPGPKey], then return an empty list. */
    val secretKeys: List<OpenPGPSecretKey> =
        if (keys.isSecretKey) {
            (keys as OpenPGPKey).secretKeys.values.toList()
        } else listOf()

    /** List of valid public component keys. */
    val validSubkeys: List<OpenPGPComponentKey> = keys.getValidKeys(referenceDate)

    /** List of valid user-IDs. */
    val validUserIds: List<String> = keys.getValidUserIds(referenceDate).map { it.userId }

    /** List of valid and expired user-IDs. */
    val validAndExpiredUserIds: List<String> = userIds

    /** List of email addresses that can be extracted from the user-IDs. */
    val emailAddresses: List<String> =
        userIds.mapNotNull {
            PATTERN_EMAIL_FROM_USERID.matcher(it).let { m1 ->
                if (m1.find()) m1.group(1)
                else
                    PATTERN_EMAIL_EXPLICIT.matcher(it).let { m2 ->
                        if (m2.find()) m2.group(1) else null
                    }
            }
        }

    /** Newest direct-key self-signature on the primary key. */
    val latestDirectKeySelfSignature: PGPSignature? =
        primaryKey.getLatestDirectKeySelfSignature(referenceDate)?.signature

    /** Newest primary-key revocation self-signature. */
    val revocationSelfSignature: PGPSignature? =
        primaryKey.getLatestKeyRevocationSelfSignature(referenceDate)?.signature

    /** Public-key encryption-algorithm of the primary key. */
    val algorithm: PublicKeyAlgorithm =
        PublicKeyAlgorithm.requireFromId(primaryKey.pgpPublicKey.algorithm)

    /** Creation date of the primary key. */
    val creationDate: Date = primaryKey.creationTime!!

    /** Latest date at which the key was modified (either by adding a subkey or self-signature). */
    val lastModified: Date = keys.lastModificationDate

    /** True, if the underlying key is a [OpenPGPKey]. */
    val isSecretKey: Boolean = keys.isSecretKey

    /** True, if there are no encrypted secret keys. */
    val isFullyDecrypted: Boolean =
        !isSecretKey ||
            secretKeys.all { it.pgpSecretKey.hasDummyS2K() || it.pgpSecretKey.isDecrypted() }

    /** True, if there are only encrypted secret keys. */
    val isFullyEncrypted: Boolean =
        isSecretKey &&
            secretKeys.none { !it.pgpSecretKey.hasDummyS2K() && it.pgpSecretKey.isDecrypted() }

    /** List of public keys, whose secret key counterparts can be used to decrypt messages. */
    val decryptionSubkeys: List<OpenPGPComponentKey> =
        keys.keys
            .asSequence()
            .filter {
                if (!it.keyIdentifier.matchesExplicit(keyIdentifier)) {
                    if (it.getLatestSelfSignature(referenceDate) == null) {
                        LOGGER.debug("Subkey ${it.keyIdentifier} has no binding signature.")
                        return@filter false
                    }
                }
                if (!it.pgpPublicKey.isEncryptionKey) {
                    LOGGER.debug("(Sub-?)Key ${it.keyIdentifier} is not encryption-capable.")
                    return@filter false
                }
                return@filter true
            }
            .toList()

    /** Expiration date of the primary key. */
    val primaryKeyExpirationDate: Date?
        get() {
            val directKeyExpirationDate: Date? =
                latestDirectKeySelfSignature?.let {
                    getKeyExpirationTimeAsDate(it, primaryKey.pgpPublicKey)
                }
            val possiblyExpiredPrimaryUserId = getPossiblyExpiredPrimaryUserId()
            val primaryUserIdCertification =
                possiblyExpiredPrimaryUserId?.let { getLatestUserIdCertification(it) }
            val userIdExpirationDate: Date? =
                primaryUserIdCertification?.let {
                    getKeyExpirationTimeAsDate(it, primaryKey.pgpPublicKey)
                }

            if (latestDirectKeySelfSignature == null && primaryUserIdCertification == null) {
                throw NoSuchElementException(
                    "No direct-key signature and no user-id signature found.")
            }
            if (directKeyExpirationDate != null && userIdExpirationDate == null) {
                return directKeyExpirationDate
            }
            if (directKeyExpirationDate == null) {
                return userIdExpirationDate
            }
            return if (directKeyExpirationDate < userIdExpirationDate) directKeyExpirationDate
            else userIdExpirationDate
        }

    /** List of all subkeys that can be used to sign a message. */
    val signingSubkeys: List<OpenPGPComponentKey> = keys.getSigningKeys(referenceDate)

    /** Whether the key is usable for encryption. */
    val isUsableForEncryption: Boolean =
        keys.getComponentKeysWithFlag(referenceDate, EncryptionPurpose.ANY.code).isNotEmpty()

    /**
     * Whether the key is capable of signing messages. This field is also true, if the key contains
     * a subkey that is capable of signing messages, but where the secret key is unavailable, e.g.
     * because it was moved to a smart-card.
     *
     * To check for keys that are actually usable to sign messages, use [isUsableForSigning].
     */
    val isSigningCapable: Boolean = isKeyValidlyBound(keyIdentifier) && signingSubkeys.isNotEmpty()

    /** Whether the key is actually usable to sign messages. */
    val isUsableForSigning: Boolean =
        isSigningCapable && signingSubkeys.any { isSecretKeyAvailable(it.keyIdentifier) }

    /**
     * True, if the [OpenPGPCertificate] can be used to certify other
     * [OpenPGPCertificates][OpenPGPCertificate].
     */
    val isUsableForThirdPartyCertification: Boolean =
        isKeyValidlyBound(keyIdentifier) &&
            getKeyFlagsOf(keyIdentifier).contains(KeyFlag.CERTIFY_OTHER)

    /** [HashAlgorithm] preferences of the primary user-ID or if absent, of the primary key. */
    val preferredHashAlgorithms: Set<HashAlgorithm>?
        get() =
            primaryUserId?.let { getPreferredHashAlgorithms(it) }
                ?: getPreferredHashAlgorithms(keyIdentifier)

    /**
     * [SymmetricKeyAlgorithm] preferences of the primary user-ID or if absent of the primary key.
     */
    val preferredSymmetricKeyAlgorithms: Set<SymmetricKeyAlgorithm>?
        get() =
            primaryUserId?.let { getPreferredSymmetricKeyAlgorithms(it) }
                ?: getPreferredSymmetricKeyAlgorithms(keyIdentifier)

    /** [CompressionAlgorithm] preferences of the primary user-ID or if absent, the primary key. */
    val preferredCompressionAlgorithms: Set<CompressionAlgorithm>?
        get() =
            primaryUserId?.let { getPreferredCompressionAlgorithms(it) }
                ?: getPreferredCompressionAlgorithms(keyIdentifier)

    /** [AEADCipherMode] preferences of the primary user-id, or if absent, the primary key. */
    val preferredAEADCipherSuites: Set<AEADCipherMode>?
        get() =
            primaryUserId?.let { getPreferredAEADCipherSuites(it) }
                ?: getPreferredAEADCipherSuites(keyIdentifier)

    /**
     * Return the expiration date of the subkey with the provided fingerprint.
     *
     * @param fingerprint subkey fingerprint
     * @return expiration date or null
     */
    fun getSubkeyExpirationDate(fingerprint: OpenPgpFingerprint): Date? {
        return getSubkeyExpirationDate(fingerprint.keyIdentifier)
    }

    /**
     * Return the expiration date of the [OpenPGPComponentKey] with the provided [keyIdentifier].
     *
     * @param keyIdentifier subkey KeyIdentifier
     * @return expiration date
     */
    fun getSubkeyExpirationDate(keyIdentifier: KeyIdentifier): Date? {
        if (primaryKey.keyIdentifier.matchesExplicit(keyIdentifier)) return primaryKeyExpirationDate
        val subkey =
            getPublicKey(keyIdentifier)
                ?: throw NoSuchElementException("No subkey with key-ID ${keyIdentifier} found.")
        val bindingSig =
            getCurrentSubkeyBindingSignature(keyIdentifier)
                ?: throw AssertionError("Subkey has no valid binding signature.")
        return bindingSig.getKeyExpirationDate(subkey.creationTime)
    }

    /**
     * Return the expiration date of the subkey with the provided keyId.
     *
     * @param keyId subkey keyId
     * @return expiration date
     */
    @Deprecated("Pass in a KeyIdentifer instead.")
    fun getSubkeyExpirationDate(keyId: Long): Date? {
        return getSubkeyExpirationDate(KeyIdentifier(keyId))
    }

    /**
     * Return the date after which the key can no longer be used to perform the given use-case,
     * caused by expiration.
     *
     * @return expiration date for the given use-case
     */
    fun getExpirationDateForUse(use: KeyFlag): Date? {
        require(use != KeyFlag.SPLIT && use != KeyFlag.SHARED) {
            "SPLIT and SHARED are not uses, but properties."
        }

        val primaryKeyExpiration = primaryKeyExpirationDate
        val keysWithFlag: List<OpenPGPComponentKey> = getKeysWithKeyFlag(use)
        if (keysWithFlag.isEmpty())
            throw NoSuchElementException("No key with the required key flag found.")

        var nonExpiring = false
        val latestSubkeyExpiration =
            keysWithFlag
                .map { key ->
                    getSubkeyExpirationDate(key.keyIdentifier).also {
                        if (it == null) nonExpiring = true
                    }
                }
                .filterNotNull()
                .maxByOrNull { it }

        if (nonExpiring) return primaryKeyExpiration
        return if (primaryKeyExpiration == null) latestSubkeyExpiration
        else if (latestSubkeyExpiration == null) primaryKeyExpiration
        else minOf(primaryKeyExpiration, latestSubkeyExpiration)
    }

    /**
     * Return true, if the given user-ID is hard-revoked.
     *
     * @return true, if the given user-ID is hard-revoked.
     */
    fun isHardRevoked(userId: CharSequence): Boolean {
        return keys
            .getUserId(userId.toString())
            ?.getLatestSelfSignature(referenceDate)
            ?.isHardRevocation
            ?: false
    }

    /**
     * Return a list of all keys which carry the provided key flag in their signature.
     *
     * @param flag flag
     * @return keys with flag
     */
    fun getKeysWithKeyFlag(flag: KeyFlag): List<OpenPGPComponentKey> =
        publicKeys.filter { getKeyFlagsOf(it.keyIdentifier).contains(flag) }

    /**
     * Return a list of all subkeys which can be used to encrypt a message for the given user-ID.
     *
     * @return encryption subkeys
     */
    fun getEncryptionSubkeys(
        userId: CharSequence?,
        purpose: EncryptionPurpose
    ): List<OpenPGPComponentKey> {
        if (userId != null && !isUserIdValid(userId)) {
            throw UnboundUserIdException(
                OpenPgpFingerprint.of(primaryKey.pgpPublicKey),
                userId.toString(),
                getLatestUserIdCertification(userId),
                getUserIdRevocation(userId))
        }
        return getEncryptionSubkeys(purpose)
    }

    /**
     * Return a list of all subkeys which can be used to encrypt a message, given the purpose.
     *
     * @return subkeys which can be used for encryption
     */
    fun getEncryptionSubkeys(purpose: EncryptionPurpose): List<OpenPGPComponentKey> {
        primaryKeyExpirationDate?.let {
            if (it < referenceDate) {
                LOGGER.debug(
                    "Certificate is expired: Primary key is expired on ${DateUtil.formatUTCDate(it)}")
                return listOf()
            }
        }

        return keys.keys
            .asSequence()
            .filter {
                if (!isKeyValidlyBound(it.keyIdentifier)) {
                    LOGGER.debug("(Sub?)-Key ${it.keyIdentifier} is not validly bound.")
                    return@filter false
                }

                getSubkeyExpirationDate(it.keyIdentifier)?.let { exp ->
                    if (exp < referenceDate) {
                        LOGGER.debug(
                            "(Sub?)-Key ${it.keyIdentifier} is expired on ${DateUtil.formatUTCDate(exp)}.")
                        return@filter false
                    }
                }

                if (!it.pgpPublicKey.isEncryptionKey) {
                    LOGGER.debug(
                        "(Sub?)-Key ${it.keyIdentifier} algorithm is not capable of encryption.")
                    return@filter false
                }

                val keyFlags = getKeyFlagsOf(it.keyIdentifier)
                when (purpose) {
                    EncryptionPurpose.COMMUNICATIONS ->
                        return@filter keyFlags.contains(KeyFlag.ENCRYPT_COMMS)
                    EncryptionPurpose.STORAGE ->
                        return@filter keyFlags.contains(KeyFlag.ENCRYPT_STORAGE)
                    EncryptionPurpose.ANY ->
                        return@filter keyFlags.contains(KeyFlag.ENCRYPT_COMMS) ||
                            keyFlags.contains(KeyFlag.ENCRYPT_STORAGE)
                }
            }
            .toList()
    }

    /**
     * Return, whether the key is usable for encryption, given the purpose.
     *
     * @return true, if the key can be used to encrypt a message according to the
     *   encryption-purpose.
     */
    fun isUsableForEncryption(purpose: EncryptionPurpose): Boolean {
        return isKeyValidlyBound(keyIdentifier) && getEncryptionSubkeys(purpose).isNotEmpty()
    }

    /**
     * Return the primary user-ID, even if it is possibly expired.
     *
     * @return possibly expired primary user-ID
     */
    fun getPossiblyExpiredPrimaryUserId(): String? =
        primaryUserId
            ?: userIds
                .mapNotNull { userId -> getLatestUserIdCertification(userId)?.let { userId to it } }
                .sortedByDescending { it.second.creationTime }
                .maxByOrNull { it.second.hashedSubPackets.isPrimaryUserID }
                ?.first

    /** Return the most-recently created self-signature on the key. */
    private fun getMostRecentSignature(): PGPSignature? =
        keys.components.map { it.latestSelfSignature }.maxByOrNull { it.creationTime }?.signature
    /**
     * Return the creation time of the latest added subkey.
     *
     * @return latest key creation time
     */
    fun getLatestKeyCreationDate(): Date =
        keys.getValidKeys(referenceDate).maxByOrNull { it.creationTime }?.creationTime
            ?: throw AssertionError("Apparently there is no validly bound key in this key ring.")

    /**
     * Return the latest certification self-signature for the given user-ID.
     *
     * @return latest self-certification for the given user-ID.
     */
    fun getLatestUserIdCertification(userId: CharSequence): PGPSignature? =
        keys.getUserId(userId.toString())?.getCertification(referenceDate)?.signature

    /**
     * Return the latest revocation self-signature for the given user-ID
     *
     * @return latest user-ID revocation for the given user-ID
     */
    fun getUserIdRevocation(userId: CharSequence): PGPSignature? =
        keys.getUserId(userId.toString())?.getRevocation(referenceDate)?.signature

    /**
     * Return the current binding signature for the subkey with the given [keyIdentifier].
     *
     * @param keyIdentifier subkey identifier
     * @return current subkey binding signature
     */
    fun getCurrentSubkeyBindingSignature(keyIdentifier: KeyIdentifier): PGPSignature? =
        keys.getKey(keyIdentifier)?.getCertification(referenceDate)?.signature

    /**
     * Return the current binding signature for the subkey with the given key-ID.
     *
     * @param keyId key-ID
     * @return current subkey binding signature
     */
    @Deprecated("Pass in a KeyIdentifier instead.")
    fun getCurrentSubkeyBindingSignature(keyId: Long): PGPSignature? =
        getCurrentSubkeyBindingSignature(KeyIdentifier(keyId))

    /**
     * Return the current revocation signature for the subkey with the given [keyIdentifier].
     *
     * @param keyIdentifier subkey identifier
     * @return current subkey revocation signature
     */
    fun getSubkeyRevocationSignature(keyIdentifier: KeyIdentifier): PGPSignature? =
        keys.getKey(keyIdentifier)?.getRevocation(referenceDate)?.signature

    /**
     * Return the current revocation signature for the subkey with the given key-ID.
     *
     * @return current subkey revocation signature
     */
    @Deprecated("Pass in a KeyIdentifier instead.")
    fun getSubkeyRevocationSignature(keyId: Long): PGPSignature? =
        getSubkeyRevocationSignature(KeyIdentifier(keyId))

    /**
     * Return a list of [KeyFlags][KeyFlag] that apply to the subkey with the provided
     * [keyIdentifier].
     *
     * @param keyIdentifier keyIdentifier
     * @return list of key flags
     */
    fun getKeyFlagsOf(keyIdentifier: KeyIdentifier): List<KeyFlag> =
        if (primaryKey.keyIdentifier.matchesExplicit(keyIdentifier)) {
            latestDirectKeySelfSignature?.let { sig ->
                SignatureSubpacketsUtil.parseKeyFlags(sig)?.let { flags ->
                    return flags
                }
            }

            primaryUserId?.let {
                SignatureSubpacketsUtil.parseKeyFlags(getLatestUserIdCertification(it))?.let { flags
                    ->
                    return flags
                }
            }
            listOf()
        } else {
            getCurrentSubkeyBindingSignature(keyIdentifier)?.let {
                SignatureSubpacketsUtil.parseKeyFlags(it)?.let { flags ->
                    return flags
                }
            }
            listOf()
        }

    /**
     * Return a list of [KeyFlags][KeyFlag] that apply to the subkey with the provided key id.
     *
     * @param keyId key-id
     * @return list of key flags
     */
    @Deprecated("Pass in a KeyIdentifier instead.")
    fun getKeyFlagsOf(keyId: Long): List<KeyFlag> = getKeyFlagsOf(KeyIdentifier(keyId))

    /**
     * Return a list of [KeyFlags][KeyFlag] that apply to the given user-id.
     *
     * @param userId user-id
     * @return key flags
     */
    fun getKeyFlagsOf(userId: CharSequence): List<KeyFlag> =
        if (!isUserIdValid(userId)) {
            listOf()
        } else {
            getLatestUserIdCertification(userId)?.let {
                SignatureSubpacketsUtil.parseKeyFlags(it) ?: listOf()
            }
                ?: throw AssertionError(
                    "While user-id '$userId' was reported as valid, there appears to be no certification for it.")
        }

    /**
     * Return the [OpenPGPComponentKey] with the given [keyIdentifier] from this
     * [OpenPGPCertificate] or [OpenPGPKey].
     *
     * @param keyIdentifier keyIdentifier
     * @return public component key or null
     */
    fun getPublicKey(keyIdentifier: KeyIdentifier): OpenPGPComponentKey? =
        keys.getKey(keyIdentifier)

    /**
     * Return the public key with the given key id from the provided key ring.
     *
     * @param keyId key id
     * @return public key or null
     */
    @Deprecated("Pass in a KeyIdentifier instead.")
    fun getPublicKey(keyId: Long): OpenPGPComponentKey? = getPublicKey(KeyIdentifier(keyId))

    /**
     * Return the [OpenPGPSecretKey] component with the given [keyIdentifier].
     *
     * @param keyIdentifier keyIdentifier
     * @return secret key or null
     */
    fun getSecretKey(keyIdentifier: KeyIdentifier): OpenPGPSecretKey? =
        if (keys.isSecretKey) {
            (keys as OpenPGPKey).getSecretKey(keyIdentifier)
        } else null

    /**
     * Return the secret key with the given key id.
     *
     * @param keyId key id
     * @return secret key or null
     */
    @Deprecated("Pass in a KeyIdentifier instead.")
    fun getSecretKey(keyId: Long): OpenPGPSecretKey? = getSecretKey(KeyIdentifier(keyId))

    /**
     * Return true, if the secret-key with the given [keyIdentifier] is available (i.e. part of the
     * certificate AND not moved to a smart-card).
     *
     * @return availability of the secret key
     */
    fun isSecretKeyAvailable(keyIdentifier: KeyIdentifier): Boolean {
        return getSecretKey(keyIdentifier)?.let {
            return if (it.pgpSecretKey.s2K == null) true // Unencrypted key
            else it.pgpSecretKey.s2K.type !in 100..110 // Secret key on smart-card
        }
            ?: false // Missing secret key
    }

    @Deprecated("Pass in a KeyIdentifier instead.")
    fun isSecretKeyAvailable(keyId: Long): Boolean {
        return isSecretKeyAvailable(KeyIdentifier(keyId))
    }

    /**
     * Return the public key with the given fingerprint.
     *
     * @param fingerprint fingerprint
     * @return public key or null
     */
    fun getPublicKey(fingerprint: OpenPgpFingerprint): OpenPGPComponentKey? =
        keys.getKey(fingerprint.keyIdentifier)

    /**
     * Return the secret key with the given fingerprint.
     *
     * @param fingerprint fingerprint
     * @return secret key or null
     */
    fun getSecretKey(fingerprint: OpenPgpFingerprint): OpenPGPSecretKey? =
        getSecretKey(fingerprint.keyIdentifier)

    /**
     * Return the public key matching the given [SubkeyIdentifier].
     *
     * @return public key
     * @throws IllegalArgumentException if the identifier's primary key does not match the primary
     *   key of the key.
     */
    fun getPublicKey(identifier: SubkeyIdentifier): OpenPGPComponentKey? {
        require(primaryKey.keyIdentifier.matchesExplicit(identifier.keyIdentifier)) {
            "Mismatching primary key ID."
        }
        return getPublicKey(identifier.componentKeyIdentifier)
    }

    /**
     * Return the secret key matching the given [SubkeyIdentifier].
     *
     * @return secret key
     * @throws IllegalArgumentException if the identifier's primary key does not match the primary
     *   key of the key.
     */
    fun getSecretKey(identifier: SubkeyIdentifier): OpenPGPComponentKey? {
        require(primaryKey.keyIdentifier.matchesExplicit(identifier.keyIdentifier)) {
            "Mismatching primary key ID."
        }
        return getSecretKey(identifier.componentKeyIdentifier)
    }

    /**
     * Return true if the [OpenPGPComponentKey] with the given [keyIdentifier] is bound to the
     * [OpenPGPCertificate] properly.
     *
     * @param keyIdentifier identifier of the component key
     * @return true if key is bound validly
     */
    fun isKeyValidlyBound(keyIdentifier: KeyIdentifier): Boolean {
        return keys.getKey(keyIdentifier)?.isBoundAt(referenceDate) ?: false
    }

    /**
     * Return true if the public key with the given key id is bound to the key ring properly.
     *
     * @param keyId key id
     * @return true if key is bound validly
     */
    @Deprecated("Pass in a KeyIdentifier instead.")
    fun isKeyValidlyBound(keyId: Long): Boolean = isKeyValidlyBound(KeyIdentifier(keyId))

    /**
     * Return the current primary user-id of the key ring.
     *
     * <p>
     * Note: If no user-id is marked as primary key using a
     * [org.bouncycastle.bcpg.sig.PrimaryUserID] packet, this method returns the first user-id on
     * the key, otherwise null.
     *
     * @return primary user-id or null
     */
    private fun findPrimaryUserId(): String? {
        return keys.primaryKey.getExplicitOrImplicitPrimaryUserId(referenceDate)?.userId
    }

    /**
     * Return true, if the primary user-ID, as well as the given user-ID are valid and bound.
     *
     * @param userId user-id
     * @return true if the primary user-ID and the given user-ID are valid.
     */
    fun isUserIdValid(userId: CharSequence): Boolean {
        var valid = isUserIdBound(userId)
        if (primaryUserId != null) valid = valid && isUserIdBound(primaryUserId)
        valid = valid && isKeyValidlyBound(primaryKey.keyIdentifier)
        return valid
    }

    /**
     * Return true, if the given user-ID is validly bound.
     *
     * @param userId user-id
     * @return true if the user-id is validly bound to the [OpenPGPCertificate]
     */
    fun isUserIdBound(userId: CharSequence): Boolean =
        keys.getUserId(userId.toString())?.isBoundAt(referenceDate) ?: false

    /**
     * Return the [HashAlgorithm] preferences of the given [userId].
     *
     * @param userId user-id
     * @return ordered set of preferred [HashAlgorithms][HashAlgorithm] (descending order)
     */
    fun getPreferredHashAlgorithms(userId: CharSequence): Set<HashAlgorithm>? {
        return (keys.getUserId(userId.toString())
                ?: throw NoSuchElementException("No user-id '$userId' found on this key."))
            .getHashAlgorithmPreferences(referenceDate)
            ?.toHashAlgorithms()
    }

    /**
     * Return the [HashAlgorithm] preferences of the component key with the given [KeyIdentifier].
     *
     * @param keyIdentifier identifier of a [OpenPGPComponentKey]
     * @return ordered set of preferred [HashAlgorithms][HashAlgorithm] (descending order)
     */
    fun getPreferredHashAlgorithms(keyIdentifier: KeyIdentifier): Set<HashAlgorithm>? {
        return (keys.getKey(keyIdentifier)
                ?: throw NoSuchElementException(
                    "No subkey with key-id $keyIdentifier found on this key."))
            .getHashAlgorithmPreferences(referenceDate)
            ?.toHashAlgorithms()
    }

    /** [HashAlgorithm] preferences of the given key. */
    @Deprecated("Pass KeyIdentifier instead.")
    fun getPreferredHashAlgorithms(keyId: Long): Set<HashAlgorithm>? {
        return getPreferredHashAlgorithms(KeyIdentifier(keyId))
    }

    /**
     * Return the [SymmetricKeyAlgorithm] preferences of the given [userId].
     *
     * @param userId user-id
     * @return ordered set of preferred [SymmetricKeyAlgorithms][SymmetricKeyAlgorithm] (descending
     *   order)
     */
    fun getPreferredSymmetricKeyAlgorithms(userId: CharSequence): Set<SymmetricKeyAlgorithm>? {
        return (keys.getUserId(userId.toString())
                ?: throw NoSuchElementException("No user-id '$userId' found on this key."))
            .getSymmetricCipherPreferences(referenceDate)
            ?.toSymmetricKeyAlgorithms()
    }

    /**
     * Return the [SymmetricKeyAlgorithm] preferences of the [OpenPGPComponentKey] with the given
     * [keyIdentifier].
     *
     * @param keyIdentifier identifier of the [OpenPGPComponentKey]
     * @return ordered set of preferred [SymmetricKeyAlgorithms][SymmetricKeyAlgorithm] (descending
     *   order)
     */
    fun getPreferredSymmetricKeyAlgorithms(
        keyIdentifier: KeyIdentifier
    ): Set<SymmetricKeyAlgorithm>? {
        return (keys.getKey(keyIdentifier)
                ?: throw NoSuchElementException(
                    "No subkey with key-id $keyIdentifier found on this key."))
            .getSymmetricCipherPreferences(referenceDate)
            ?.toSymmetricKeyAlgorithms()
    }

    /** [SymmetricKeyAlgorithm] preferences of the given key. */
    @Deprecated("Pass KeyIdentifier instead.")
    fun getPreferredSymmetricKeyAlgorithms(keyId: Long): Set<SymmetricKeyAlgorithm>? {
        return getPreferredSymmetricKeyAlgorithms(KeyIdentifier(keyId))
    }

    /**
     * Return the [CompressionAlgorithm] preferences of the given [userId].
     *
     * @param userId user-id
     * @return ordered set of preferred [CompressionAlgorithms][CompressionAlgorithm] (descending
     *   order)
     */
    fun getPreferredCompressionAlgorithms(userId: CharSequence): Set<CompressionAlgorithm>? {
        return (keys.getUserId(userId.toString())
                ?: throw NoSuchElementException("No user-id '$userId' found on this key."))
            .getCompressionAlgorithmPreferences(referenceDate)
            ?.toCompressionAlgorithms()
    }

    /**
     * Return the [CompressionAlgorithm] preferences of the [OpenPGPComponentKey] with the given
     * [keyIdentifier].
     *
     * @param keyIdentifier identifier of the [OpenPGPComponentKey]
     * @return ordered set of preferred [CompressionAlgorithms][CompressionAlgorithm] (descending
     *   order)
     */
    fun getPreferredCompressionAlgorithms(
        keyIdentifier: KeyIdentifier
    ): Set<CompressionAlgorithm>? {
        return (keys.getKey(keyIdentifier)
                ?: throw NoSuchElementException(
                    "No subkey with key-id $keyIdentifier found on this key."))
            .getCompressionAlgorithmPreferences(referenceDate)
            ?.toCompressionAlgorithms()
    }

    /** [CompressionAlgorithm] preferences of the given key. */
    @Deprecated("Pass in a KeyIdentifier instead.")
    fun getPreferredCompressionAlgorithms(keyId: Long): Set<CompressionAlgorithm>? {
        return getPreferredCompressionAlgorithms(KeyIdentifier(keyId))
    }

    /**
     * Return the [AEADCipherMode] preferences of the given [userId].
     *
     * @param userId user-ID
     * @return ordered set of [AEADCipherModes][AEADCipherMode] (descending order, including
     *   implicitly supported AEAD modes)
     */
    fun getPreferredAEADCipherSuites(userId: CharSequence): Set<AEADCipherMode>? {
        return (keys.getUserId(userId.toString())
                ?: throw NoSuchElementException("No user-id '$userId' found on this key."))
            .getAEADCipherSuitePreferences(referenceDate)
            ?.toAEADCipherModes()
    }

    /**
     * Return the [AEADCipherMode] preferences of the [OpenPGPComponentKey] with the given
     * [keyIdentifier].
     *
     * @param keyIdentifier component key identifier
     * @return ordered set of [AEADCipherModes][AEADCipherMode] (descending order, including
     *   implicitly supported AEAD modes)
     */
    fun getPreferredAEADCipherSuites(keyIdentifier: KeyIdentifier): Set<AEADCipherMode>? {
        return (keys.getKey(keyIdentifier)
                ?: throw NoSuchElementException(
                    "No subkey with key-id $keyIdentifier found on this key."))
            .getAEADCipherSuitePreferences(referenceDate)
            ?.toAEADCipherModes()
    }

    @Deprecated("Pass KeyIdentifier instead.")
    fun getPreferredAEADCipherSuites(keyId: Long): Set<AEADCipherMode>? {
        return getPreferredAEADCipherSuites(KeyIdentifier(keyId))
    }

    companion object {

        /** Evaluate the key for the given signature. */
        @JvmStatic
        fun evaluateForSignature(keys: PGPKeyRing, signature: PGPSignature) =
            KeyRingInfo(keys, signature.creationTime!!)

        private val PATTERN_EMAIL_FROM_USERID =
            "<([a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+@[a-zA-Z0-9.-]+)>".toPattern()
        private val PATTERN_EMAIL_EXPLICIT =
            "^([a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+@[a-zA-Z0-9.-]+)$".toPattern()

        @JvmStatic private val LOGGER = LoggerFactory.getLogger(KeyRingInfo::class.java)
    }
}
