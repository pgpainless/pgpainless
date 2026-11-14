// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing

import java.util.*
import org.bouncycastle.openpgp.api.MessageEncryptionMechanism
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey
import org.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.EncryptionPurpose
import org.pgpainless.algorithm.negotiation.EncryptionMechanismNegotiator
import org.pgpainless.algorithm.negotiation.SymmetricKeyAlgorithmNegotiator.Companion.byPopularity
import org.pgpainless.authentication.CertificateAuthority
import org.pgpainless.exception.KeyException.ExpiredKeyException
import org.pgpainless.exception.KeyException.UnacceptableEncryptionKeyException
import org.pgpainless.exception.KeyException.UnacceptableSelfSignatureException
import org.pgpainless.key.SubkeyIdentifier
import org.pgpainless.key.info.KeyAccessor
import org.pgpainless.key.info.KeyRingInfo
import org.pgpainless.util.Passphrase

class EncryptionOptions
private constructor(private val purpose: EncryptionPurpose, private val api: PGPainless) {

    var encryptionMechanismNegotiator: EncryptionMechanismNegotiator =
        EncryptionMechanismNegotiator.modificationDetectionOrBetter(byPopularity())
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
            .forEach { addRecipient(it.certificate, userId).also { foundAcceptable = true } }
        require(foundAcceptable) {
            "Could not identify any trust-worthy certificates for '$userId' and target trust amount $targetAmount."
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

        var encryptionSubkeys = info.getEncryptionSubkeys(purpose)
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

        // Apply selection by user
        encryptionSubkeys = selector.selectEncryptionSubkeys(encryptionSubkeys)

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

    fun overrideEncryptionMechanism(encryptionMechanism: MessageEncryptionMechanism) = apply {
        require(
            api.algorithmPolicy.messageEncryptionAlgorithmPolicy.isAcceptable(
                encryptionMechanism)) {
                "Provided symmetric encryption algorithm is not acceptable."
            }
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

    fun usesOnlyPasswordBasedEncryption() =
        _encryptionMethods.all { it is PBEKeyEncryptionMethodGenerator }

    internal fun negotiateEncryptionMechanism(): MessageEncryptionMechanism {
        if (encryptionMechanismOverride != null) {
            return encryptionMechanismOverride!!
        }

        val features = keysAndAccessors.values.map { it.features }.toList()
        val aeadAlgorithms = keysAndAccessors.values.map { it.preferredAEADCipherSuites }.toList()
        val symmetricKeyAlgorithms =
            keysAndAccessors.values.map { it.preferredSymmetricKeyAlgorithms }.toList()

        val mechanism =
            encryptionMechanismNegotiator.negotiate(
                api.algorithmPolicy,
                encryptionMechanismOverride,
                features,
                aeadAlgorithms,
                symmetricKeyAlgorithms)

        return mechanism
    }

    fun interface EncryptionKeySelector {
        fun selectEncryptionSubkeys(
            encryptionCapableKeys: List<OpenPGPComponentKey>
        ): List<OpenPGPComponentKey>
    }

    companion object {
        // TODO: Remove in 2.2
        @JvmStatic
        @Deprecated("Deprecated in favor of method taking api instance.")
        fun get() = get(PGPainless.getInstance())

        @JvmStatic fun get(api: PGPainless) = EncryptionOptions(api)

        // TODO: Remove in 2.2
        @JvmStatic
        @Deprecated("Deprecated in favor of method taking api instance.")
        fun encryptCommunications() = encryptCommunications(PGPainless.getInstance())

        @JvmStatic
        fun encryptCommunications(api: PGPainless) =
            EncryptionOptions(EncryptionPurpose.COMMUNICATIONS, api)

        // TODO: Remove in 2.2
        @JvmStatic
        @Deprecated("Deprecated in favor of method taking api instance.")
        fun encryptDataAtRest() = encryptDataAtRest(PGPainless.getInstance())

        @JvmStatic
        fun encryptDataAtRest(api: PGPainless) = EncryptionOptions(EncryptionPurpose.STORAGE, api)

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
