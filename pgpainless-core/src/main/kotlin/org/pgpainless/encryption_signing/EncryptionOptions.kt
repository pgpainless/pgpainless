// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing

import java.util.*
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.api.MessageEncryptionMechanism
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.AEADAlgorithm
import org.pgpainless.algorithm.AEADCipherMode
import org.pgpainless.algorithm.EncryptionPurpose
import org.pgpainless.algorithm.Feature
import org.pgpainless.algorithm.SymmetricKeyAlgorithm
import org.pgpainless.algorithm.negotiation.SymmetricKeyAlgorithmNegotiator.Companion.byPopularity
import org.pgpainless.authentication.CertificateAuthority
import org.pgpainless.encryption_signing.EncryptionOptions.EncryptionKeySelector
import org.pgpainless.exception.KeyException.*
import org.pgpainless.key.SubkeyIdentifier
import org.pgpainless.key.info.KeyAccessor
import org.pgpainless.key.info.KeyRingInfo
import org.pgpainless.util.Passphrase

class EncryptionOptions(private val purpose: EncryptionPurpose, private val api: PGPainless) {
    private val _encryptionMethods: MutableSet<PGPKeyEncryptionMethodGenerator> = mutableSetOf()
    private val keysAndAccessors: MutableMap<OpenPGPComponentKey, KeyAccessor> = mutableMapOf()
    private val _keyRingInfo: MutableMap<SubkeyIdentifier, KeyRingInfo> = mutableMapOf()
    private val encryptionKeySelector: EncryptionKeySelector = encryptToAllCapableSubkeys()

    private var allowEncryptionWithMissingKeyFlags = false
    private var evaluationDate = Date()
    private var _encryptionMechanismOverride: MessageEncryptionMechanism? = null

    val encryptionMethods
        get() = _encryptionMethods.toSet()

    val encryptionKeyIdentifiers
        get() = keysAndAccessors.keys.map { SubkeyIdentifier(it) }

    val encryptionKeys
        get() = keysAndAccessors.keys.toSet()

    @Deprecated(
        "Deprecated in favor of encryptionMechanismOverride",
        replaceWith = ReplaceWith("encryptionMechanismOverride"))
    val encryptionAlgorithmOverride
        get() =
            _encryptionMechanismOverride?.let {
                SymmetricKeyAlgorithm.requireFromId(it.symmetricKeyAlgorithm)
            }

    val encryptionMechanismOverride
        get() = _encryptionMechanismOverride

    constructor(api: PGPainless) : this(EncryptionPurpose.ANY, api)

    /**
     * Set the evaluation date for certificate evaluation.
     *
     * @param evaluationDate reference time
     * @return this
     */
    fun setEvaluationDate(evaluationDate: Date) = apply { this.evaluationDate = evaluationDate }

    /**
     * Identify authenticatable certificates for the given user-ID by querying the
     * [CertificateAuthority] for identifiable bindings. Add all acceptable bindings, whose trust
     * amount is larger or equal to the target amount to the list of recipients.
     *
     * @param userId userId
     * @param email if true, treat the user-ID as an email address and match all user-IDs containing
     *   the mail address
     * @param authority certificate authority
     * @param targetAmount target amount (120 = fully authenticated, 240 = doubly authenticated, 60
     *   = partially authenticated...)
     * @return encryption options
     */
    @JvmOverloads
    fun addAuthenticatableRecipients(
        userId: String,
        email: Boolean,
        authority: CertificateAuthority,
        targetAmount: Int = 120
    ) = apply {
        var foundAcceptable = false
        authority
            .lookupByUserId(userId, email, evaluationDate, targetAmount)
            .filter { it.isAuthenticated() }
            .forEach {
                addRecipient(api.toCertificate(it.certificate)).also { foundAcceptable = true }
            }
        require(foundAcceptable) {
            "Could not identify any trust-worthy certificates for '$userId' and target trust amount $targetAmount."
        }
    }

    /**
     * Add all key rings in the provided [Iterable] (e.g.
     * [org.bouncycastle.openpgp.PGPPublicKeyRingCollection]) as recipients. Note: This method is
     * deprecated. Instead, repeatedly call [addRecipient], passing in individual
     * [OpenPGPCertificate] instances.
     *
     * @param keys keys
     * @return this
     */
    @Deprecated("Repeatedly pass OpenPGPCertificate instances instead.")
    fun addRecipients(keys: Iterable<PGPPublicKeyRing>) = apply {
        keys.toList().let {
            require(it.isNotEmpty()) { "Set of recipient keys cannot be empty." }
            it.forEach { key -> addRecipient(key) }
        }
    }

    /**
     * Add all key rings in the provided [Iterable] (e.g.
     * [org.bouncycastle.openpgp.PGPPublicKeyRingCollection]) as recipients. Per key ring, the
     * selector is applied to select one or more encryption subkeys. Note: This method is
     * deprecated. Instead, repeatedly call [addRecipient], passing in individual
     * [OpenPGPCertificate] instances.
     *
     * @param keys keys
     * @param selector encryption key selector
     * @return this
     */
    @Deprecated("Repeatedly pass OpenPGPCertificate instances instead.")
    fun addRecipients(keys: Iterable<PGPPublicKeyRing>, selector: EncryptionKeySelector) = apply {
        keys.toList().let {
            require(it.isNotEmpty()) { "Set of recipient keys cannot be empty." }
            it.forEach { key -> addRecipient(key, selector) }
        }
    }

    /**
     * Encrypt the message to the recipients [OpenPGPCertificate].
     *
     * @param cert recipient certificate
     * @return this
     */
    fun addRecipient(cert: OpenPGPCertificate) = addRecipient(cert, encryptionKeySelector)

    /**
     * Add a recipient by providing a key.
     *
     * @param key key ring
     * @return this
     */
    @Deprecated(
        "Pass in OpenPGPCertificate instead.",
        replaceWith =
            ReplaceWith("addRecipient(key.toOpenPGPCertificate(), encryptionKeySelector)"))
    fun addRecipient(key: PGPPublicKeyRing) = addRecipient(key, encryptionKeySelector)

    /**
     * Encrypt the message for the given recipients [OpenPGPCertificate], sourcing algorithm
     * preferences by inspecting the binding signature on the passed [userId].
     *
     * @param cert recipient certificate
     * @param userId recipient user-id
     * @return this
     */
    fun addRecipient(cert: OpenPGPCertificate, userId: CharSequence) =
        addRecipient(cert, userId, encryptionKeySelector)

    /**
     * Add a recipient by providing a key and recipient user-id. The user-id is used to determine
     * the recipients preferences (algorithms etc.). Note: This method is deprecated. Replace the
     * [PGPPublicKeyRing] instance with an [OpenPGPCertificate].
     *
     * @param key key ring
     * @param userId user id
     * @return this
     */
    @Deprecated(
        "Pass in OpenPGPCertificate instead.",
        replaceWith = ReplaceWith("addRecipient(key.toOpenPGPCertificate(), userId)"))
    fun addRecipient(key: PGPPublicKeyRing, userId: CharSequence) =
        addRecipient(key, userId, encryptionKeySelector)

    /**
     * Encrypt the message for the given recipients [OpenPGPCertificate], sourcing algorithm
     * preferences by inspecting the binding signature on the given [userId] and filtering the
     * recipient subkeys through the given [EncryptionKeySelector].
     *
     * @param cert recipient certificate
     * @param userId user-id for sourcing algorithm preferences
     * @param encryptionKeySelector decides which subkeys to encrypt for
     * @return this
     */
    fun addRecipient(
        cert: OpenPGPCertificate,
        userId: CharSequence,
        encryptionKeySelector: EncryptionKeySelector
    ) = apply {
        val info = api.inspect(cert, evaluationDate)
        val subkeys =
            encryptionKeySelector.selectEncryptionSubkeys(
                info.getEncryptionSubkeys(userId, purpose))
        if (subkeys.isEmpty()) {
            throw UnacceptableEncryptionKeyException(cert)
        }

        for (subkey in subkeys) {
            val keyId = SubkeyIdentifier(subkey)
            _keyRingInfo[keyId] = info
            val accessor = KeyAccessor.ViaUserId(subkey, cert.getUserId(userId.toString()))
            addRecipientKey(subkey, accessor, false)
        }
    }

    /**
     * Encrypt the message for the given recipients public key, sourcing algorithm preferences by
     * inspecting the binding signature on the given [userId] and filtering the recipient subkeys
     * through the given [EncryptionKeySelector].
     *
     * @param key recipient public key
     * @param userId user-id for sourcing algorithm preferences
     * @param encryptionKeySelector decides which subkeys to encrypt for
     * @return this
     */
    @Deprecated(
        "Pass in OpenPGPCertificate instead.",
        replaceWith =
            ReplaceWith("addRecipient(key.toOpenPGPCertificate(), userId, encryptionKeySelector)"))
    fun addRecipient(
        key: PGPPublicKeyRing,
        userId: CharSequence,
        encryptionKeySelector: EncryptionKeySelector
    ) = addRecipient(api.toCertificate(key), userId, encryptionKeySelector)

    /**
     * Encrypt the message for the given recipients [OpenPGPCertificate], filtering encryption
     * subkeys through the given [EncryptionKeySelector].
     *
     * @param cert recipient certificate
     * @param encryptionKeySelector decides, which subkeys to encrypt for
     * @return this
     */
    fun addRecipient(cert: OpenPGPCertificate, encryptionKeySelector: EncryptionKeySelector) =
        addAsRecipient(cert, encryptionKeySelector, false)

    /**
     * Encrypt the message for the given recipients public key, filtering encryption subkeys through
     * the given [EncryptionKeySelector].
     *
     * @param key recipient public key
     * @param encryptionKeySelector decides, which subkeys to encrypt for
     * @return this
     */
    @Deprecated(
        "Pass in OpenPGPCertificate instead.",
        replaceWith =
            ReplaceWith("addRecipient(key.toOpenPGPCertificate(), encryptionKeySelector)"))
    fun addRecipient(key: PGPPublicKeyRing, encryptionKeySelector: EncryptionKeySelector) =
        addRecipient(api.toCertificate(key), encryptionKeySelector)

    /**
     * Encrypt the message for the recipients [OpenPGPCertificate], keeping the recipient anonymous
     * by setting a wildcard key-id / fingerprint.
     *
     * @param cert recipient certificate
     * @param selector decides, which subkeys to encrypt for
     * @return this
     */
    @JvmOverloads
    fun addHiddenRecipient(
        cert: OpenPGPCertificate,
        selector: EncryptionKeySelector = encryptionKeySelector
    ) = addAsRecipient(cert, selector, true)

    /**
     * Encrypt the message for the recipients public key, keeping the recipient anonymous by setting
     * a wildcard key-id / fingerprint.
     *
     * @param key recipient public key
     * @param selector decides, which subkeys to encrypt for
     * @return this
     */
    @JvmOverloads
    @Deprecated(
        "Pass in an OpenPGPCertificate instead.",
        replaceWith = ReplaceWith("addHiddenRecipient(key.toOpenPGPCertificate(), selector)"))
    fun addHiddenRecipient(
        key: PGPPublicKeyRing,
        selector: EncryptionKeySelector = encryptionKeySelector
    ) = addHiddenRecipient(api.toCertificate(key), selector)

    private fun addAsRecipient(
        cert: OpenPGPCertificate,
        selector: EncryptionKeySelector,
        wildcardKeyId: Boolean
    ) = apply {
        val info = api.inspect(cert, evaluationDate)
        val primaryKeyExpiration =
            try {
                info.primaryKeyExpirationDate
            } catch (e: NoSuchElementException) {
                throw UnacceptableSelfSignatureException(cert)
            }

        if (primaryKeyExpiration != null && primaryKeyExpiration < evaluationDate) {
            throw ExpiredKeyException(cert, primaryKeyExpiration)
        }

        var encryptionSubkeys = selector.selectEncryptionSubkeys(info.getEncryptionSubkeys(purpose))

        // There are some legacy keys around without key flags.
        // If we allow encryption for those keys, we add valid keys without any key flags, if they
        // are
        // capable of encryption by means of their algorithm
        if (encryptionSubkeys.isEmpty() && allowEncryptionWithMissingKeyFlags) {
            encryptionSubkeys =
                info.validSubkeys
                    .filter { it.pgpPublicKey.isEncryptionKey }
                    .filter { info.getKeyFlagsOf(it.keyIdentifier).isEmpty() }
        }

        if (encryptionSubkeys.isEmpty()) {
            throw UnacceptableEncryptionKeyException(cert)
        }

        for (subkey in encryptionSubkeys) {
            val keyId = SubkeyIdentifier(subkey)
            _keyRingInfo[keyId] = info
            val accessor = KeyAccessor.ViaKeyIdentifier(subkey)
            addRecipientKey(subkey, accessor, wildcardKeyId)
        }
    }

    private fun addRecipientKey(
        key: OpenPGPComponentKey,
        accessor: KeyAccessor,
        wildcardRecipient: Boolean
    ) {
        keysAndAccessors[key] = accessor
        addEncryptionMethod(
            api.implementation.publicKeyKeyEncryptionMethodGenerator(key.pgpPublicKey).also {
                it.setUseWildcardRecipient(wildcardRecipient)
            })
    }

    /**
     * Add a symmetric passphrase which the message will be encrypted to.
     *
     * @param passphrase passphrase
     * @return this
     */
    @Deprecated(
        "Deprecated in favor of addMessagePassphrase",
        ReplaceWith("addMessagePassphrase(passphrase)"))
    fun addPassphrase(passphrase: Passphrase) = addMessagePassphrase(passphrase)

    /**
     * Add a symmetric passphrase which the message will be encrypted to.
     *
     * @param passphrase passphrase
     * @return this
     */
    fun addMessagePassphrase(passphrase: Passphrase) = apply {
        require(!passphrase.isEmpty) { "Passphrase MUST NOT be empty." }
        addEncryptionMethod(
            api.implementation.pbeKeyEncryptionMethodGenerator(passphrase.getChars()))
    }

    /**
     * Add a [PGPKeyEncryptionMethodGenerator] which will be used to encrypt the message. Method
     * generators are either [org.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator]
     * (passphrase) or [PGPKeyEncryptionMethodGenerator] (public key).
     *
     * This method is intended for advanced users to allow encryption for specific subkeys. This can
     * come in handy for example if data needs to be encrypted to a subkey that's ignored by
     * PGPainless.
     *
     * @param encryptionMethod encryption method
     * @return this
     */
    fun addEncryptionMethod(encryptionMethod: PGPKeyEncryptionMethodGenerator) = apply {
        _encryptionMethods.add(encryptionMethod)
    }

    /**
     * Override the used symmetric encryption algorithm. The symmetric encryption algorithm is used
     * to encrypt the message itself, while the used symmetric key will be encrypted to all
     * recipients using public key cryptography.
     *
     * If the algorithm is not overridden, a suitable algorithm will be negotiated.
     *
     * @param encryptionAlgorithm encryption algorithm override
     * @return this
     */
    @Deprecated(
        "Deprecated in favor of overrideEncryptionMechanism",
        replaceWith =
            ReplaceWith(
                "overrideEncryptionMechanism(MessageEncryptionMechanism.integrityProtected(encryptionAlgorithm.algorithmId))"))
    fun overrideEncryptionAlgorithm(encryptionAlgorithm: SymmetricKeyAlgorithm) = apply {
        require(encryptionAlgorithm != SymmetricKeyAlgorithm.NULL) {
            "Encryption algorithm override cannot be NULL."
        }
        overrideEncryptionMechanism(
            MessageEncryptionMechanism.integrityProtected(encryptionAlgorithm.algorithmId))
    }

    fun overrideEncryptionMechanism(encryptionMechanism: MessageEncryptionMechanism) = apply {
        _encryptionMechanismOverride = encryptionMechanism
    }

    /**
     * If this method is called, subsequent calls to [addRecipient] will allow encryption for
     * subkeys that do not carry any [org.pgpainless.algorithm.KeyFlag] subpacket. This is a
     * workaround for dealing with legacy keys that have no key flags subpacket but rely on the key
     * algorithm type to convey the subkeys use.
     *
     * @return this
     */
    fun setAllowEncryptionWithMissingKeyFlags() = apply {
        this.allowEncryptionWithMissingKeyFlags = true
    }

    fun hasEncryptionMethod() = _encryptionMethods.isNotEmpty()

    internal fun negotiateSymmetricEncryptionAlgorithm(): SymmetricKeyAlgorithm {
        val preferences =
            keysAndAccessors.values.map { it.preferredSymmetricKeyAlgorithms }.toList()
        val algorithm =
            byPopularity()
                .negotiate(
                    api.algorithmPolicy.symmetricKeyEncryptionAlgorithmPolicy,
                    encryptionAlgorithmOverride,
                    preferences)
        return algorithm
    }

    internal fun negotiateEncryptionMechanism(): MessageEncryptionMechanism {
        if (encryptionMechanismOverride != null) {
            return encryptionMechanismOverride!!
        }

        val features = keysAndAccessors.values.map { it.features }.toList()

        if (features.all { it.contains(Feature.MODIFICATION_DETECTION_2) }) {
            val aeadPrefs = keysAndAccessors.values.map { it.preferredAEADCipherSuites }.toList()
            val counted = mutableMapOf<AEADCipherMode, Int>()
            for (pref in aeadPrefs) {
                for (mode in pref) {
                    counted[mode] = counted.getOrDefault(mode, 0) + 1
                }
            }
            val max: AEADCipherMode =
                counted.maxByOrNull { it.value }?.key
                    ?: AEADCipherMode(AEADAlgorithm.OCB, SymmetricKeyAlgorithm.AES_128)
            return MessageEncryptionMechanism.aead(
                max.ciphermode.algorithmId, max.aeadAlgorithm.algorithmId)
        } else {
            return MessageEncryptionMechanism.integrityProtected(
                negotiateSymmetricEncryptionAlgorithm().algorithmId)
        }
    }

    fun interface EncryptionKeySelector {
        fun selectEncryptionSubkeys(
            encryptionCapableKeys: List<OpenPGPComponentKey>
        ): List<OpenPGPComponentKey>
    }

    companion object {
        @JvmOverloads
        @JvmStatic
        fun get(api: PGPainless = PGPainless.getInstance()) = EncryptionOptions(api)

        @JvmOverloads
        @JvmStatic
        fun encryptCommunications(api: PGPainless = PGPainless.getInstance()) =
            EncryptionOptions(EncryptionPurpose.COMMUNICATIONS, api)

        @JvmOverloads
        @JvmStatic
        fun encryptDataAtRest(api: PGPainless = PGPainless.getInstance()) =
            EncryptionOptions(EncryptionPurpose.STORAGE, api)

        /**
         * Only encrypt to the first valid encryption capable subkey we stumble upon.
         *
         * @return encryption key selector
         */
        @JvmStatic
        fun encryptToFirstSubkey() = EncryptionKeySelector { encryptionCapableKeys ->
            encryptionCapableKeys.firstOrNull()?.let { listOf(it) } ?: listOf()
        }

        /**
         * Encrypt to any valid, encryption capable subkey on the key ring.
         *
         * @return encryption key selector
         */
        @JvmStatic
        fun encryptToAllCapableSubkeys() = EncryptionKeySelector { encryptionCapableKeys ->
            encryptionCapableKeys
        }
    }
}
