// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.info

import java.util.*
import openpgp.openPgpKeyId
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.*
import org.pgpainless.bouncycastle.extensions.*
import org.pgpainless.exception.KeyException.UnboundUserIdException
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.SubkeyIdentifier
import org.pgpainless.key.util.KeyRingUtils
import org.pgpainless.policy.Policy
import org.pgpainless.signature.consumer.SignaturePicker
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil.Companion.getKeyExpirationTimeAsDate
import org.pgpainless.util.DateUtil
import org.slf4j.LoggerFactory

class KeyRingInfo(
    val keys: OpenPGPCertificate,
    val policy: Policy = PGPainless.getPolicy(),
    val referenceDate: Date = Date()
) {

    constructor(
        keys: PGPKeyRing,
        policy: Policy = PGPainless.getPolicy(),
        referenceDate: Date = Date()
    ) : this(OpenPGPCertificate(keys), policy, referenceDate)

    @JvmOverloads
    constructor(
        keys: PGPKeyRing,
        referenceDate: Date = Date()
    ) : this(keys, PGPainless.getPolicy(), referenceDate)

    private val signatures: Signatures = Signatures(keys.pgpKeyRing, referenceDate, policy)

    /** Primary [PGPPublicKey]. */
    val publicKey: PGPPublicKey = keys.primaryKey.pgpPublicKey

    /** Primary key ID. */
    val keyId: Long = publicKey.keyID

    /** Primary key fingerprint. */
    val fingerprint: OpenPgpFingerprint = OpenPgpFingerprint.of(publicKey)

    /** All User-IDs (valid, expired, revoked). */
    val userIds: List<String> = KeyRingUtils.getUserIdsIgnoringInvalidUTF8(publicKey)

    /** Primary User-ID. */
    val primaryUserId = keys.getPrimaryUserId(referenceDate)?.userId

    /** Revocation State. */
    val revocationState = signatures.primaryKeyRevocation.toRevocationState()
    /**
     * Return the date on which the primary key was revoked, or null if it has not yet been revoked.
     *
     * @return revocation date or null
     */
    val revocationDate: Date? =
        if (revocationState.isSoftRevocation()) revocationState.date else null

    /**
     * Primary [PGPSecretKey] of this key ring or null if the key ring is not a [PGPSecretKeyRing].
     */
    val secretKey: PGPSecretKey? =
        when (keys.pgpKeyRing) {
            is PGPSecretKeyRing -> (keys.pgpKeyRing as PGPSecretKeyRing).secretKey!!
            else -> null
        }

    /** OpenPGP key version. */
    val version: Int = publicKey.version

    /**
     * Return all [PGPPublicKeys][PGPPublicKey] of this key ring. The first key in the list being
     * the primary key. Note that the list is unmodifiable.
     *
     * @return list of public keys
     */
    val publicKeys: List<PGPPublicKey> = keys.pgpKeyRing.publicKeys.asSequence().toList()

    /** All secret keys. If the key ring is a [PGPPublicKeyRing], then return an empty list. */
    val secretKeys: List<PGPSecretKey> =
        when (keys.pgpKeyRing) {
            is PGPSecretKeyRing ->
                (keys.pgpKeyRing as PGPSecretKeyRing).secretKeys.asSequence().toList()
            else -> listOf()
        }

    /** List of valid public subkeys. */
    val validSubkeys: List<PGPPublicKey> =
        keys.publicKeys.values.filter { it.isBoundAt(referenceDate) }.map { it.pgpPublicKey }

    /** List of valid user-IDs. */
    val validUserIds: List<String> = keys.getValidUserIds(referenceDate).map { it.userId }

    /** List of valid and expired user-IDs. */
    val validAndExpiredUserIds: List<String> =
        userIds.filter {
            val certification = signatures.userIdCertifications[it] ?: return@filter false
            val revocation = signatures.userIdRevocations[it] ?: return@filter true
            return@filter !revocation.isHardRevocation &&
                certification.creationTime > revocation.creationTime
        }

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
    val latestDirectKeySelfSignature: PGPSignature? = signatures.primaryKeySelfSignature

    /** Newest primary-key revocation self-signature. */
    val revocationSelfSignature: PGPSignature? = signatures.primaryKeyRevocation

    /** Public-key encryption-algorithm of the primary key. */
    val algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.requireFromId(publicKey.algorithm)

    /** Creation date of the primary key. */
    val creationDate: Date = publicKey.creationTime!!

    /** Latest date at which the key was modified (either by adding a subkey or self-signature). */
    val lastModified: Date = keys.lastModificationDate

    /** True, if the underlying keyring is a [PGPSecretKeyRing]. */
    val isSecretKey: Boolean = keys.pgpKeyRing is PGPSecretKeyRing

    /** True, if there are no encrypted secret keys. */
    val isFullyDecrypted: Boolean =
        !isSecretKey || secretKeys.all { it.hasDummyS2K() || it.isDecrypted() }

    /** True, if there are only encrypted secret keys. */
    val isFullyEncrypted: Boolean =
        isSecretKey && secretKeys.none { !it.hasDummyS2K() && it.isDecrypted() }

    /** List of public keys, whose secret key counterparts can be used to decrypt messages. */
    val decryptionSubkeys: List<PGPPublicKey> =
        keys.pgpKeyRing.publicKeys
            .asSequence()
            .filter {
                if (it.keyID != keyId) {
                    if (signatures.subkeyBindings[it.keyID] == null) {
                        LOGGER.debug("Subkey ${it.keyID.openPgpKeyId()} has no binding signature.")
                        return@filter false
                    }
                }
                if (!it.isEncryptionKey) {
                    LOGGER.debug("(Sub-?)Key ${it.keyID.openPgpKeyId()} is not encryption-capable.")
                    return@filter false
                }
                return@filter true
            }
            .toList()

    /** Expiration date of the primary key. */
    val primaryKeyExpirationDate: Date?
        get() {
            val directKeyExpirationDate: Date? =
                latestDirectKeySelfSignature?.let { getKeyExpirationTimeAsDate(it, publicKey) }
            val possiblyExpiredPrimaryUserId = getPossiblyExpiredPrimaryUserId()
            val primaryUserIdCertification =
                possiblyExpiredPrimaryUserId?.let { getLatestUserIdCertification(it) }
            val userIdExpirationDate: Date? =
                primaryUserIdCertification?.let { getKeyExpirationTimeAsDate(it, publicKey) }

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
    val signingSubkeys: List<PGPPublicKey> =
        keys.getSigningKeys(referenceDate).map { it.pgpPublicKey }

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
    val isSigningCapable: Boolean = isKeyValidlyBound(keyId) && signingSubkeys.isNotEmpty()

    /** Whether the key is actually usable to sign messages. */
    val isUsableForSigning: Boolean =
        isSigningCapable && signingSubkeys.any { isSecretKeyAvailable(it.keyID) }

    /** [HashAlgorithm] preferences of the primary user-ID or if absent, of the primary key. */
    val preferredHashAlgorithms: Set<HashAlgorithm>
        get() =
            primaryUserId?.let { getPreferredHashAlgorithms(it) }
                ?: getPreferredHashAlgorithms(keyId)

    /**
     * [SymmetricKeyAlgorithm] preferences of the primary user-ID or if absent of the primary key.
     */
    val preferredSymmetricKeyAlgorithms: Set<SymmetricKeyAlgorithm>
        get() =
            primaryUserId?.let { getPreferredSymmetricKeyAlgorithms(it) }
                ?: getPreferredSymmetricKeyAlgorithms(keyId)

    /** [CompressionAlgorithm] preferences of the primary user-ID or if absent, the primary key. */
    val preferredCompressionAlgorithms: Set<CompressionAlgorithm>
        get() =
            primaryUserId?.let { getPreferredCompressionAlgorithms(it) }
                ?: getPreferredCompressionAlgorithms(keyId)

    /**
     * Return the expiration date of the subkey with the provided fingerprint.
     *
     * @param fingerprint subkey fingerprint
     * @return expiration date or null
     */
    fun getSubkeyExpirationDate(fingerprint: OpenPgpFingerprint): Date? {
        return getSubkeyExpirationDate(fingerprint.keyId)
    }

    /**
     * Return the expiration date of the subkey with the provided keyId.
     *
     * @param keyId subkey keyId
     * @return expiration date
     */
    fun getSubkeyExpirationDate(keyId: Long): Date? {
        if (publicKey.keyID == keyId) return primaryKeyExpirationDate
        val subkey =
            getPublicKey(keyId)
                ?: throw NoSuchElementException(
                    "No subkey with key-ID ${keyId.openPgpKeyId()} found.")
        val bindingSig =
            getCurrentSubkeyBindingSignature(keyId)
                ?: throw AssertionError("Subkey has no valid binding signature.")
        return bindingSig.getKeyExpirationDate(subkey.creationTime)
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
        val keysWithFlag: List<PGPPublicKey> = getKeysWithKeyFlag(use)
        if (keysWithFlag.isEmpty())
            throw NoSuchElementException("No key with the required key flag found.")

        var nonExpiring = false
        val latestSubkeyExpiration =
            keysWithFlag
                .map { key ->
                    getSubkeyExpirationDate(key.keyID).also { if (it == null) nonExpiring = true }
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
        return signatures.userIdRevocations[userId]?.isHardRevocation ?: false
    }

    /**
     * Return a list of all keys which carry the provided key flag in their signature.
     *
     * @param flag flag
     * @return keys with flag
     */
    fun getKeysWithKeyFlag(flag: KeyFlag): List<PGPPublicKey> =
        publicKeys.filter { getKeyFlagsOf(it.keyID).contains(flag) }

    /**
     * Return a list of all subkeys which can be used to encrypt a message for the given user-ID.
     *
     * @return encryption subkeys
     */
    fun getEncryptionSubkeys(
        userId: CharSequence?,
        purpose: EncryptionPurpose
    ): List<PGPPublicKey> {
        if (userId != null && !isUserIdValid(userId)) {
            throw UnboundUserIdException(
                OpenPgpFingerprint.of(publicKey),
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
    fun getEncryptionSubkeys(purpose: EncryptionPurpose): List<PGPPublicKey> {
        primaryKeyExpirationDate?.let {
            if (it < referenceDate) {
                LOGGER.debug(
                    "Certificate is expired: Primary key is expired on ${DateUtil.formatUTCDate(it)}")
                return listOf()
            }
        }

        return keys.pgpKeyRing.publicKeys
            .asSequence()
            .filter {
                if (!isKeyValidlyBound(it.keyID)) {
                    LOGGER.debug("(Sub?)-Key ${it.keyID.openPgpKeyId()} is not validly bound.")
                    return@filter false
                }

                getSubkeyExpirationDate(it.keyID)?.let { exp ->
                    if (exp < referenceDate) {
                        LOGGER.debug(
                            "(Sub?)-Key ${it.keyID.openPgpKeyId()} is expired on ${DateUtil.formatUTCDate(exp)}.")
                        return@filter false
                    }
                }

                if (!it.isEncryptionKey) {
                    LOGGER.debug(
                        "(Sub?)-Key ${it.keyID.openPgpKeyId()} algorithm is not capable of encryption.")
                    return@filter false
                }

                val keyFlags = getKeyFlagsOf(it.keyID)
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
        return isKeyValidlyBound(keyId) && getEncryptionSubkeys(purpose).isNotEmpty()
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
        setOfNotNull(latestDirectKeySelfSignature, revocationSelfSignature)
            .asSequence()
            .plus(signatures.userIdCertifications.values)
            .plus(signatures.userIdRevocations.values)
            .plus(signatures.subkeyBindings.values)
            .plus(signatures.subkeyRevocations.values)
            .maxByOrNull { it.creationTime }
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
     * Return the current binding signature for the subkey with the given key-ID.
     *
     * @return current subkey binding signature
     */
    fun getCurrentSubkeyBindingSignature(keyId: Long): PGPSignature? =
        signatures.subkeyBindings[keyId]

    /**
     * Return the current revocation signature for the subkey with the given key-ID.
     *
     * @return current subkey revocation signature
     */
    fun getSubkeyRevocationSignature(keyId: Long): PGPSignature? =
        signatures.subkeyRevocations[keyId]

    /**
     * Return a list of [KeyFlags][KeyFlag] that apply to the subkey with the provided key id.
     *
     * @param keyId key-id
     * @return list of key flags
     */
    fun getKeyFlagsOf(keyId: Long): List<KeyFlag> =
        if (keyId == publicKey.keyID) {
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
            getCurrentSubkeyBindingSignature(keyId)?.let {
                SignatureSubpacketsUtil.parseKeyFlags(it)?.let { flags ->
                    return flags
                }
            }
            listOf()
        }

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
     * Return the public key with the given key id from the provided key ring.
     *
     * @param keyId key id
     * @return public key or null
     */
    fun getPublicKey(keyId: Long): PGPPublicKey? = keys.pgpKeyRing.getPublicKey(keyId)

    /**
     * Return the secret key with the given key id.
     *
     * @param keyId key id
     * @return secret key or null
     */
    fun getSecretKey(keyId: Long): PGPSecretKey? =
        when (keys.pgpKeyRing) {
            is PGPSecretKeyRing -> (keys.pgpKeyRing as PGPSecretKeyRing).getSecretKey(keyId)
            else -> null
        }

    /**
     * Return true, if the secret-key with the given key-ID is available (i.e. not moved to a
     * smart-card).
     *
     * @return availability of the secret key
     */
    fun isSecretKeyAvailable(keyId: Long): Boolean {
        return getSecretKey(keyId)?.let {
            return if (it.s2K == null) true // Unencrypted key
            else it.s2K.type !in 100..110 // Secret key on smart-card
        }
            ?: false // Missing secret key
    }

    /**
     * Return the public key with the given fingerprint.
     *
     * @param fingerprint fingerprint
     * @return public key or null
     */
    fun getPublicKey(fingerprint: OpenPgpFingerprint): PGPPublicKey? =
        keys.pgpKeyRing.getPublicKey(fingerprint.keyId)

    /**
     * Return the secret key with the given fingerprint.
     *
     * @param fingerprint fingerprint
     * @return secret key or null
     */
    fun getSecretKey(fingerprint: OpenPgpFingerprint): PGPSecretKey? =
        when (keys.pgpKeyRing) {
            is PGPSecretKeyRing ->
                (keys.pgpKeyRing as PGPSecretKeyRing).getSecretKey(fingerprint.keyId)
            else -> null
        }

    /**
     * Return the public key matching the given [SubkeyIdentifier].
     *
     * @return public key
     * @throws IllegalArgumentException if the identifier's primary key does not match the primary
     *   key of the key.
     */
    fun getPublicKey(identifier: SubkeyIdentifier): PGPPublicKey? {
        require(identifier.primaryKeyIdentifier.keyId == publicKey.keyID) {
            "Mismatching primary key ID."
        }
        return getPublicKey(identifier.subkeyId)
    }

    /**
     * Return the secret key matching the given [SubkeyIdentifier].
     *
     * @return secret key
     * @throws IllegalArgumentException if the identifier's primary key does not match the primary
     *   key of the key.
     */
    fun getSecretKey(identifier: SubkeyIdentifier): PGPSecretKey? =
        when (keys.pgpKeyRing) {
            is PGPSecretKeyRing -> {
                require(identifier.primaryKeyIdentifier.keyId == publicKey.keyID) {
                    "Mismatching primary key ID."
                }
                (keys.pgpKeyRing as PGPSecretKeyRing).getSecretKey(identifier.subkeyIdentifier)
            }
            else -> null
        }

    /**
     * Return true if the public key with the given key id is bound to the key ring properly.
     *
     * @param keyId key id
     * @return true if key is bound validly
     */
    fun isKeyValidlyBound(keyId: Long): Boolean {
        val publicKey = keys.pgpKeyRing.getPublicKey(keyId) ?: return false

        // Primary key -> Check Primary Key Revocation
        if (publicKey.keyID == this.publicKey.keyID) {
            return if (signatures.primaryKeyRevocation != null &&
                signatures.primaryKeyRevocation.isHardRevocation) {
                false
            } else signatures.primaryKeyRevocation == null
        }

        // Else Subkey -> Check Subkey Revocation
        val binding = signatures.subkeyBindings[keyId]
        val revocation = signatures.subkeyRevocations[keyId]

        // No valid binding
        if (binding == null || binding.isExpired(referenceDate)) {
            return false
        }

        // Revocation
        return if (revocation != null) {
            if (revocation.isHardRevocation) {
                // Subkey is hard revoked
                false
            } else {
                // Key is soft-revoked, not yet re-bound
                (revocation.isExpired(referenceDate) ||
                    !revocation.creationTime.after(binding.creationTime))
            }
        } else true
    }

    /**
     * Return the current primary user-id of the key ring.
     *
     * <p>
     * Note: If no user-id is marked as primary key using a [PrimaryUserID] packet, this method
     * returns the first user-id on the key, otherwise null.
     *
     * @return primary user-id or null
     */
    private fun findPrimaryUserId(): String? {
        if (userIds.isEmpty()) {
            return null
        }

        return signatures.userIdCertifications
            .filter { (_, certification) -> certification.hashedSubPackets.isPrimaryUserID }
            .entries
            .maxByOrNull { (_, certification) -> certification.creationTime }
            ?.key
            ?: signatures.userIdCertifications.keys.firstOrNull()
    }

    /** Return true, if the primary user-ID, as well as the given user-ID are valid and bound. */
    fun isUserIdValid(userId: CharSequence) =
        if (primaryUserId == null) {
            false
        } else {
            isUserIdBound(primaryUserId) &&
                (if (userId == primaryUserId) true else isUserIdBound(userId))
        }

    /** Return true, if the given user-ID is validly bound. */
    fun isUserIdBound(userId: CharSequence) =
        signatures.userIdCertifications[userId]?.let { sig ->
            if (sig.isExpired(referenceDate)) {
                // certification expired
                return false
            }
            if (sig.hashedSubPackets.isPrimaryUserID) {
                getKeyExpirationTimeAsDate(sig, publicKey)?.let { expirationDate ->
                    // key expired?
                    if (expirationDate < referenceDate) return false
                }
            }
            signatures.userIdRevocations[userId]?.let { rev ->
                if (rev.isHardRevocation) {
                    return false // hard revoked -> invalid
                }
                sig.creationTime > rev.creationTime // re-certification after soft revocation?
            }
                ?: true // certification, but no revocation
        }
            ?: false // no certification

    /** [HashAlgorithm] preferences of the given user-ID. */
    fun getPreferredHashAlgorithms(userId: CharSequence): Set<HashAlgorithm> {
        return getKeyAccessor(userId, keyId).preferredHashAlgorithms
    }

    /** [HashAlgorithm] preferences of the given key. */
    fun getPreferredHashAlgorithms(keyId: Long): Set<HashAlgorithm> {
        return KeyAccessor.SubKey(this, SubkeyIdentifier(keys.pgpKeyRing, keyId))
            .preferredHashAlgorithms
    }

    /** [SymmetricKeyAlgorithm] preferences of the given user-ID. */
    fun getPreferredSymmetricKeyAlgorithms(userId: CharSequence): Set<SymmetricKeyAlgorithm> {
        return getKeyAccessor(userId, keyId).preferredSymmetricKeyAlgorithms
    }

    /** [SymmetricKeyAlgorithm] preferences of the given key. */
    fun getPreferredSymmetricKeyAlgorithms(keyId: Long): Set<SymmetricKeyAlgorithm> {
        return KeyAccessor.SubKey(this, SubkeyIdentifier(keys.pgpKeyRing, keyId))
            .preferredSymmetricKeyAlgorithms
    }

    /** [CompressionAlgorithm] preferences of the given user-ID. */
    fun getPreferredCompressionAlgorithms(userId: CharSequence): Set<CompressionAlgorithm> {
        return getKeyAccessor(userId, keyId).preferredCompressionAlgorithms
    }

    /** [CompressionAlgorithm] preferences of the given key. */
    fun getPreferredCompressionAlgorithms(keyId: Long): Set<CompressionAlgorithm> {
        return KeyAccessor.SubKey(this, SubkeyIdentifier(keys.pgpKeyRing, keyId))
            .preferredCompressionAlgorithms
    }

    val isUsableForThirdPartyCertification: Boolean =
        isKeyValidlyBound(keyId) && getKeyFlagsOf(keyId).contains(KeyFlag.CERTIFY_OTHER)

    private fun getKeyAccessor(userId: CharSequence?, keyId: Long): KeyAccessor {
        if (getPublicKey(keyId) == null) {
            throw NoSuchElementException(
                "No subkey with key-id ${keyId.openPgpKeyId()} found on this key.")
        }
        if (userId != null && !userIds.contains(userId)) {
            throw NoSuchElementException("No user-id '$userId' found on this key.")
        }
        return if (userId != null) {
            KeyAccessor.ViaUserId(this, SubkeyIdentifier(keys.pgpKeyRing, keyId), userId)
        } else {
            KeyAccessor.ViaKeyId(this, SubkeyIdentifier(keys.pgpKeyRing, keyId))
        }
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

    private class Signatures(val keys: PGPKeyRing, val referenceDate: Date, val policy: Policy) {
        val primaryKeyRevocation: PGPSignature? =
            SignaturePicker.pickCurrentRevocationSelfSignature(keys, policy, referenceDate)
        val primaryKeySelfSignature: PGPSignature? =
            SignaturePicker.pickLatestDirectKeySignature(keys, policy, referenceDate)
        val userIdRevocations = mutableMapOf<String, PGPSignature>()
        val userIdCertifications = mutableMapOf<String, PGPSignature>()
        val subkeyRevocations = mutableMapOf<Long, PGPSignature>()
        val subkeyBindings = mutableMapOf<Long, PGPSignature>()

        init {
            KeyRingUtils.getUserIdsIgnoringInvalidUTF8(keys.publicKey).forEach { userId ->
                SignaturePicker.pickCurrentUserIdRevocationSignature(
                        keys, userId, policy, referenceDate)
                    ?.let { userIdRevocations[userId] = it }
                SignaturePicker.pickLatestUserIdCertificationSignature(
                        keys, userId, policy, referenceDate)
                    ?.let { userIdCertifications[userId] = it }
            }
            keys.publicKeys.asSequence().drop(1).forEach { subkey ->
                SignaturePicker.pickCurrentSubkeyBindingRevocationSignature(
                        keys, subkey, policy, referenceDate)
                    ?.let { subkeyRevocations[subkey.keyID] = it }
                SignaturePicker.pickLatestSubkeyBindingSignature(
                        keys, subkey, policy, referenceDate)
                    ?.let { subkeyBindings[subkey.keyID] = it }
            }
        }
    }
}
