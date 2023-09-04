// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing

import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator
import org.pgpainless.algorithm.EncryptionPurpose
import org.pgpainless.algorithm.SymmetricKeyAlgorithm
import org.pgpainless.authentication.CertificateAuthority
import org.pgpainless.exception.KeyException
import org.pgpainless.exception.KeyException.*
import org.pgpainless.implementation.ImplementationFactory
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.SubkeyIdentifier
import org.pgpainless.key.info.KeyAccessor
import org.pgpainless.key.info.KeyRingInfo
import org.pgpainless.util.Passphrase
import java.util.*
import javax.annotation.Nonnull


class EncryptionOptions(
        private val purpose: EncryptionPurpose
) {
    private val _encryptionMethods: MutableSet<PGPKeyEncryptionMethodGenerator> = mutableSetOf()
    private val _encryptionKeyIdentifiers: MutableSet<SubkeyIdentifier> = mutableSetOf()
    private val _keyRingInfo: MutableMap<SubkeyIdentifier, KeyRingInfo> = mutableMapOf()
    private val _keyViews: MutableMap<SubkeyIdentifier, KeyAccessor> = mutableMapOf()
    private val encryptionKeySelector: EncryptionKeySelector = encryptToAllCapableSubkeys()

    private var allowEncryptionWithMissingKeyFlags = false
    private var evaluationDate = Date()
    private var _encryptionAlgorithmOverride: SymmetricKeyAlgorithm? = null

    val encryptionMethods
        get() = _encryptionMethods.toSet()
    val encryptionKeyIdentifiers
        get() = _encryptionKeyIdentifiers.toSet()
    val keyRingInfo
        get() = _keyRingInfo.toMap()
    val keyViews
        get() = _keyViews.toMap()
    val encryptionAlgorithmOverride
        get() = _encryptionAlgorithmOverride

    constructor(): this(EncryptionPurpose.ANY)

    /**
     * Factory method to create an {@link EncryptionOptions} object which will encrypt for keys
     * which carry the flag {@link org.pgpainless.algorithm.KeyFlag#ENCRYPT_COMMS}.
     *
     * @return encryption options
     */
    fun setEvaluationDate(evaluationDate: Date) = apply {
        this.evaluationDate = evaluationDate
    }

    /**
     * Identify authenticatable certificates for the given user-ID by querying the {@link CertificateAuthority} for
     * identifiable bindings.
     * Add all acceptable bindings, whose trust amount is larger or equal to the target amount to the list of recipients.
     * @param userId userId
     * @param email if true, treat the user-ID as an email address and match all user-IDs containing the mail address
     * @param authority certificate authority
     * @param targetAmount target amount (120 = fully authenticated, 240 = doubly authenticated,
     *                    60 = partially authenticated...)
     * @return encryption options
     */
    @JvmOverloads
    fun addAuthenticatableRecipients(userId: String, email: Boolean, authority: CertificateAuthority, targetAmount: Int = 120) = apply {
        var foundAcceptable = false
        authority.lookupByUserId(userId, email, evaluationDate, targetAmount)
                .filter { it.isAuthenticated() }
                .forEach { addRecipient(it.certificate)
                        .also {
                            foundAcceptable = true
                        }
                }
        require(foundAcceptable) {
            "Could not identify any trust-worthy certificates for '$userId' and target trust amount $targetAmount."
        }
    }

    /**
     * Add all key rings in the provided {@link Iterable} (e.g. {@link PGPPublicKeyRingCollection}) as recipients.
     *
     * @param keys keys
     * @return this
     */
    fun addRecipients(keys: Iterable<PGPPublicKeyRing>) = apply {
        keys.toList().let {
            require(it.isNotEmpty()) {
                "Set of recipient keys cannot be empty."
            }
            it.forEach { key -> addRecipient(key) }
        }
    }

    /**
     * Add all key rings in the provided {@link Iterable} (e.g. {@link PGPPublicKeyRingCollection}) as recipients.
     * Per key ring, the selector is applied to select one or more encryption subkeys.
     *
     * @param keys keys
     * @param selector encryption key selector
     * @return this
     */
    fun addRecipients(keys: Iterable<PGPPublicKeyRing>, selector: EncryptionKeySelector) = apply {
        keys.toList().let {
            require(it.isNotEmpty()) {
                "Set of recipient keys cannot be empty."
            }
            it.forEach { key -> addRecipient(key, selector) }
        }
    }

    /**
     * Add a recipient by providing a key.
     *
     * @param key key ring
     * @return this
     */
    fun addRecipient(key: PGPPublicKeyRing) = addRecipient(key, encryptionKeySelector)

    /**
     * Add a recipient by providing a key and recipient user-id.
     * The user-id is used to determine the recipients preferences (algorithms etc.).
     *
     * @param key key ring
     * @param userId user id
     * @return this
     */
    fun addRecipient(key: PGPPublicKeyRing, userId: CharSequence) =
            addRecipient(key, userId, encryptionKeySelector)

    fun addRecipient(key: PGPPublicKeyRing, userId: CharSequence, encryptionKeySelector: EncryptionKeySelector) = apply {
        val info = KeyRingInfo(key, evaluationDate)
        val subkeys = encryptionKeySelector.selectEncryptionSubkeys(info.getEncryptionSubkeys(userId, purpose))
        if (subkeys.isEmpty()) {
            throw KeyException.UnacceptableEncryptionKeyException(OpenPgpFingerprint.of(key))
        }

        for (subkey in subkeys) {
            val keyId = SubkeyIdentifier(key, subkey.keyID)
            (_keyRingInfo as MutableMap)[keyId] = info
            (_keyViews as MutableMap)[keyId] = KeyAccessor.ViaUserId(info, keyId, userId.toString())
            addRecipientKey(key, subkey, false)
        }
    }

    fun addRecipient(key: PGPPublicKeyRing, encryptionKeySelector: EncryptionKeySelector) = apply {
        addAsRecipient(key, encryptionKeySelector, false)
    }

    @JvmOverloads
    fun addHiddenRecipient(key: PGPPublicKeyRing, selector: EncryptionKeySelector = encryptionKeySelector) = apply {
        addAsRecipient(key, selector, true)
    }

    private fun addAsRecipient(key: PGPPublicKeyRing, selector: EncryptionKeySelector, wildcardKeyId: Boolean) = apply {
        val info = KeyRingInfo(key, evaluationDate)
        val primaryKeyExpiration = try {
            info.primaryKeyExpirationDate
        } catch (e: NoSuchElementException) {
            throw UnacceptableSelfSignatureException(OpenPgpFingerprint.of(key))
        }

        if (primaryKeyExpiration != null && primaryKeyExpiration < evaluationDate) {
            throw ExpiredKeyException(OpenPgpFingerprint.of(key), primaryKeyExpiration)
        }

        var encryptionSubkeys = selector.selectEncryptionSubkeys(info.getEncryptionSubkeys(purpose))

        // There are some legacy keys around without key flags.
        // If we allow encryption for those keys, we add valid keys without any key flags, if they are
        // capable of encryption by means of their algorithm
        if (encryptionSubkeys.isEmpty() && allowEncryptionWithMissingKeyFlags) {
            encryptionSubkeys = info.validSubkeys
                    .filter { it.isEncryptionKey }
                    .filter { info.getKeyFlagsOf(it.keyID).isEmpty() }
        }

        if (encryptionSubkeys.isEmpty()) {
            throw UnacceptableEncryptionKeyException(OpenPgpFingerprint.of(key))
        }

        for (subkey in encryptionSubkeys) {
            val keyId = SubkeyIdentifier(key, subkey.keyID)
            (_keyRingInfo as MutableMap)[keyId] = info
            (_keyViews as MutableMap)[keyId] = KeyAccessor.ViaKeyId(info, keyId)
            addRecipientKey(key, subkey, wildcardKeyId)
        }
    }

    private fun addRecipientKey(certificate: PGPPublicKeyRing,
                                key: PGPPublicKey,
                                wildcardKeyId: Boolean) {
        (_encryptionKeyIdentifiers as MutableSet).add(SubkeyIdentifier(certificate, key.keyID))
        addEncryptionMethod(ImplementationFactory.getInstance()
                .getPublicKeyKeyEncryptionMethodGenerator(key)
                .also { it.setUseWildcardKeyID(wildcardKeyId) })
    }

    /**
     * Add a symmetric passphrase which the message will be encrypted to.
     *
     * @param passphrase passphrase
     * @return this
     */
    fun addPassphrase(passphrase: Passphrase) = apply {
        require(!passphrase.isEmpty) {
            "Passphrase MUST NOT be empty."
        }
        addEncryptionMethod(ImplementationFactory.getInstance().getPBEKeyEncryptionMethodGenerator(passphrase))
    }

    /**
     * Add an {@link PGPKeyEncryptionMethodGenerator} which will be used to encrypt the message.
     * Method generators are either {@link PBEKeyEncryptionMethodGenerator} (passphrase)
     * or {@link PGPKeyEncryptionMethodGenerator} (public key).
     *
     * This method is intended for advanced users to allow encryption for specific subkeys.
     * This can come in handy for example if data needs to be encrypted to a subkey that's ignored by PGPainless.
     *
     * @param encryptionMethod encryption method
     * @return this
     */
    fun addEncryptionMethod(encryptionMethod: PGPKeyEncryptionMethodGenerator) = apply {
        (_encryptionMethods as MutableSet).add(encryptionMethod)
    }

    /**
     * Override the used symmetric encryption algorithm.
     * The symmetric encryption algorithm is used to encrypt the message itself,
     * while the used symmetric key will be encrypted to all recipients using public key
     * cryptography.
     *
     * If the algorithm is not overridden, a suitable algorithm will be negotiated.
     *
     * @param encryptionAlgorithm encryption algorithm override
     * @return this
     */
    fun overrideEncryptionAlgorithm(encryptionAlgorithm: SymmetricKeyAlgorithm) = apply {
        require(encryptionAlgorithm != SymmetricKeyAlgorithm.NULL) {
            "Encryption algorithm override cannot be NULL."
        }
        _encryptionAlgorithmOverride = encryptionAlgorithm
    }

    /**
     * If this method is called, subsequent calls to {@link #addRecipient(PGPPublicKeyRing)} will allow encryption
     * for subkeys that do not carry any {@link org.pgpainless.algorithm.KeyFlag} subpacket.
     * This is a workaround for dealing with legacy keys that have no key flags subpacket but rely on the key algorithm
     * type to convey the subkeys use.
     *
     * @return this
     */
    fun setAllowEncryptionWithMissingKeyFlags() = apply {
        this.allowEncryptionWithMissingKeyFlags = true
    }

    fun hasEncryptionMethod() = _encryptionMethods.isNotEmpty()


    fun interface EncryptionKeySelector {
        fun selectEncryptionSubkeys(encryptionCapableKeys: List<PGPPublicKey>): List<PGPPublicKey>
    }

    companion object {
        @JvmStatic
        fun get() = EncryptionOptions()

        @JvmStatic
        fun encryptCommunications() = EncryptionOptions(EncryptionPurpose.COMMUNICATIONS)

        @JvmStatic
        fun encryptDataAtRest() = EncryptionOptions(EncryptionPurpose.STORAGE)

        /**
         * Only encrypt to the first valid encryption capable subkey we stumble upon.
         *
         * @return encryption key selector
         */
        @JvmStatic
        fun encryptToFirstSubkey() = EncryptionKeySelector { encryptionCapableKeys ->
            encryptionCapableKeys.firstOrNull()?.let { listOf(it) } ?: listOf() }

        /**
         * Encrypt to any valid, encryption capable subkey on the key ring.
         *
         * @return encryption key selector
         */
        @JvmStatic
        fun encryptToAllCapableSubkeys() = EncryptionKeySelector { encryptionCapableKeys -> encryptionCapableKeys }
    }
}