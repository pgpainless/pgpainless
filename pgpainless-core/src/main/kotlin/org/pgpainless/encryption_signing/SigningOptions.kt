// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing

import java.util.*
import org.bouncycastle.openpgp.*
import org.pgpainless.PGPainless.Companion.getPolicy
import org.pgpainless.PGPainless.Companion.inspectKeyRing
import org.pgpainless.algorithm.DocumentSignatureType
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.PublicKeyAlgorithm.Companion.requireFromId
import org.pgpainless.algorithm.negotiation.HashAlgorithmNegotiator.Companion.negotiateSignatureHashAlgorithm
import org.pgpainless.bouncycastle.extensions.unlock
import org.pgpainless.exception.KeyException
import org.pgpainless.exception.KeyException.*
import org.pgpainless.implementation.ImplementationFactory
import org.pgpainless.key.OpenPgpFingerprint.Companion.of
import org.pgpainless.key.SubkeyIdentifier
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.policy.Policy
import org.pgpainless.signature.subpackets.BaseSignatureSubpackets.Callback
import org.pgpainless.signature.subpackets.SignatureSubpackets
import org.pgpainless.signature.subpackets.SignatureSubpacketsHelper

class SigningOptions {

    val signingMethods: Map<SubkeyIdentifier, SigningMethod> = mutableMapOf()
    private var _hashAlgorithmOverride: HashAlgorithm? = null
    private var _evaluationDate: Date = Date()

    val hashAlgorithmOverride: HashAlgorithm?
        get() = _hashAlgorithmOverride

    /**
     * Override hash algorithm negotiation by dictating which hash algorithm needs to be used. If no
     * override has been set, an acceptable algorithm will be negotiated instead. Note: To override
     * the hash algorithm for signing, call this method *before* calling [addInlineSignature] or
     * [addDetachedSignature].
     *
     * @param hashAlgorithmOverride override hash algorithm
     * @return this
     */
    fun overrideHashAlgorithm(hashAlgorithmOverride: HashAlgorithm) = apply {
        _hashAlgorithmOverride = hashAlgorithmOverride
    }

    val evaluationDate: Date
        get() = _evaluationDate

    /**
     * Override the evaluation date for signing keys with the given date.
     *
     * @param evaluationDate new evaluation date
     * @return this
     */
    fun setEvaluationDate(evaluationDate: Date) = apply { _evaluationDate = evaluationDate }

    /**
     * Sign the message using an inline signature made by the provided signing key.
     *
     * @param signingKeyProtector protector to unlock the signing key
     * @param signingKey key ring containing the signing key
     * @return this
     * @throws KeyException if something is wrong with the key
     * @throws PGPException if the key cannot be unlocked or a signing method cannot be created
     */
    @Throws(KeyException::class, PGPException::class)
    fun addSignature(signingKeyProtector: SecretKeyRingProtector, signingKey: PGPSecretKeyRing) =
        apply {
            addInlineSignature(
                signingKeyProtector, signingKey, null, DocumentSignatureType.BINARY_DOCUMENT)
        }

    /**
     * Add inline signatures with all secret key rings in the provided secret key ring collection.
     *
     * @param signingKeyProtector decryptor to unlock the signing secret keys
     * @param signingKeys collection of signing keys
     * @param signatureType type of signature (binary, canonical text)
     * @return this
     * @throws KeyException if something is wrong with any of the keys
     * @throws PGPException if any of the keys cannot be unlocked or a signing method cannot be
     *   created
     */
    @Throws(KeyException::class, PGPException::class)
    fun addInlineSignatures(
        signingKeyProtector: SecretKeyRingProtector,
        signingKeys: Iterable<PGPSecretKeyRing>,
        signatureType: DocumentSignatureType
    ) = apply {
        signingKeys.forEach { addInlineSignature(signingKeyProtector, it, null, signatureType) }
    }

    /**
     * Add an inline-signature. Inline signatures are being embedded into the message itself and can
     * be processed in one pass, thanks to the use of one-pass-signature packets.
     *
     * @param signingKeyProtector decryptor to unlock the signing secret key
     * @param signingKey signing key
     * @param signatureType type of signature (binary, canonical text)
     * @return this
     * @throws KeyException if something is wrong with the key
     * @throws PGPException if the key cannot be unlocked or the signing method cannot be created
     */
    @Throws(KeyException::class, PGPException::class)
    fun addInlineSignature(
        signingKeyProtector: SecretKeyRingProtector,
        signingKey: PGPSecretKeyRing,
        signatureType: DocumentSignatureType
    ) = apply { addInlineSignature(signingKeyProtector, signingKey, null, signatureType) }

    /**
     * Add an inline-signature. Inline signatures are being embedded into the message itself and can
     * be processed in one pass, thanks to the use of one-pass-signature packets.
     *
     * <p>
     * This method uses the passed in user-id to select user-specific hash algorithms.
     *
     * @param signingKeyProtector decryptor to unlock the signing secret key
     * @param signingKey signing key
     * @param userId user-id of the signer
     * @param signatureType signature type (binary, canonical text)
     * @param subpacketsCallback callback to modify the hashed and unhashed subpackets of the
     *   signature
     * @return this
     * @throws KeyException if the key is invalid
     * @throws PGPException if the key cannot be unlocked or the signing method cannot be created
     */
    @Throws(KeyException::class, PGPException::class)
    @JvmOverloads
    fun addInlineSignature(
        signingKeyProtector: SecretKeyRingProtector,
        signingKey: PGPSecretKeyRing,
        userId: CharSequence? = null,
        signatureType: DocumentSignatureType = DocumentSignatureType.BINARY_DOCUMENT,
        subpacketsCallback: Callback? = null
    ) = apply {
        val keyRingInfo = inspectKeyRing(signingKey, evaluationDate)
        if (userId != null && !keyRingInfo.isUserIdValid(userId)) {
            throw UnboundUserIdException(
                of(signingKey),
                userId.toString(),
                keyRingInfo.getLatestUserIdCertification(userId),
                keyRingInfo.getUserIdRevocation(userId))
        }

        val signingPubKeys = keyRingInfo.signingSubkeys
        if (signingPubKeys.isEmpty()) {
            throw UnacceptableSigningKeyException(of(signingKey))
        }

        for (signingPubKey in signingPubKeys) {
            val signingSecKey: PGPSecretKey =
                signingKey.getSecretKey(signingPubKey.keyID)
                    ?: throw MissingSecretKeyException(of(signingKey), signingPubKey.keyID)
            val signingSubkey: PGPPrivateKey = signingSecKey.unlock(signingKeyProtector)
            val hashAlgorithms =
                if (userId != null) keyRingInfo.getPreferredHashAlgorithms(userId)
                else keyRingInfo.getPreferredHashAlgorithms(signingPubKey.keyID)
            val hashAlgorithm: HashAlgorithm = negotiateHashAlgorithm(hashAlgorithms, getPolicy())
            addSigningMethod(
                signingKey, signingSubkey, hashAlgorithm, signatureType, false, subpacketsCallback)
        }
    }

    /**
     * Create an inline signature using the signing key with the given keyId.
     *
     * @param signingKeyProtector decryptor to unlock the secret key
     * @param signingKey secret key ring
     * @param keyId keyId of the signing (sub-)key
     * @param signatureType signature type
     * @param subpacketsCallback callback to modify the signatures subpackets
     * @return builder
     * @throws PGPException if the secret key cannot be unlocked or if no signing method can be
     *   created.
     * @throws KeyException.UnacceptableSigningKeyException if the key ring does not carry any
     *   signing-capable subkeys
     * @throws KeyException.MissingSecretKeyException if the key ring does not contain the
     *   identified secret key
     */
    @Throws(KeyException::class, PGPException::class)
    @JvmOverloads
    fun addInlineSignature(
        signingKeyProtector: SecretKeyRingProtector,
        signingKey: PGPSecretKeyRing,
        keyId: Long,
        signatureType: DocumentSignatureType = DocumentSignatureType.BINARY_DOCUMENT,
        subpacketsCallback: Callback? = null
    ) = apply {
        val keyRingInfo = inspectKeyRing(signingKey, evaluationDate)
        val signingPubKeys = keyRingInfo.signingSubkeys
        if (signingPubKeys.isEmpty()) {
            throw UnacceptableSigningKeyException(of(signingKey))
        }

        for (signingPubKey in signingPubKeys) {
            if (signingPubKey.keyID != keyId) {
                continue
            }

            val signingSecKey =
                signingKey.getSecretKey(signingPubKey.keyID)
                    ?: throw MissingSecretKeyException(of(signingKey), signingPubKey.keyID)
            val signingSubkey = signingSecKey.unlock(signingKeyProtector)
            val hashAlgorithms = keyRingInfo.getPreferredHashAlgorithms(signingPubKey.keyID)
            val hashAlgorithm: HashAlgorithm = negotiateHashAlgorithm(hashAlgorithms, getPolicy())
            addSigningMethod(
                signingKey, signingSubkey, hashAlgorithm, signatureType, false, subpacketsCallback)
            return this
        }
        throw MissingSecretKeyException(of(signingKey), keyId)
    }

    /**
     * Add detached signatures with all key rings from the provided secret key ring collection.
     *
     * @param signingKeyProtector decryptor to unlock the secret signing keys
     * @param signingKeys collection of signing key rings
     * @param signatureType type of the signature (binary, canonical text)
     * @return this
     * @throws KeyException if something is wrong with any of the keys
     * @throws PGPException if any of the keys cannot be validated or unlocked, or if any signing
     *   method cannot be created
     */
    @Throws(KeyException::class, PGPException::class)
    fun addDetachedSignatures(
        signingKeyProtector: SecretKeyRingProtector,
        signingKeys: Iterable<PGPSecretKeyRing>,
        signatureType: DocumentSignatureType
    ) = apply {
        signingKeys.forEach { addDetachedSignature(signingKeyProtector, it, null, signatureType) }
    }

    /**
     * Create a detached signature. Detached signatures are not being added into the PGP message
     * itself. Instead, they can be distributed separately to the message. Detached signatures are
     * useful if the data that is being signed shall not be modified (e.g. when signing a file).
     *
     * @param signingKeyProtector decryptor to unlock the secret signing key
     * @param signingKey signing key
     * @param signatureType type of data that is signed (binary, canonical text)
     * @return this
     * @throws KeyException if something is wrong with the key
     * @throws PGPException if the key cannot be validated or unlocked, or if no signature method
     *   can be created
     */
    @Throws(KeyException::class, PGPException::class)
    fun addDetachedSignature(
        signingKeyProtector: SecretKeyRingProtector,
        signingKey: PGPSecretKeyRing,
        signatureType: DocumentSignatureType
    ) = apply { addDetachedSignature(signingKeyProtector, signingKey, null, signatureType) }

    /**
     * Create a detached signature. Detached signatures are not being added into the PGP message
     * itself. Instead, they can be distributed separately to the message. Detached signatures are
     * useful if the data that is being signed shall not be modified (e.g. when signing a file).
     *
     * <p>
     * This method uses the passed in user-id to select user-specific hash algorithms.
     *
     * @param signingKeyProtector decryptor to unlock the secret signing key
     * @param signingKey signing key
     * @param userId user-id
     * @param signatureType type of data that is signed (binary, canonical text)
     * @param subpacketCallback callback to modify hashed and unhashed subpackets of the signature
     * @return this
     * @throws KeyException if something is wrong with the key
     * @throws PGPException if the key cannot be validated or unlocked, or if no signature method
     *   can be created
     */
    @JvmOverloads
    @Throws(KeyException::class, PGPException::class)
    fun addDetachedSignature(
        signingKeyProtector: SecretKeyRingProtector,
        signingKey: PGPSecretKeyRing,
        userId: String? = null,
        signatureType: DocumentSignatureType = DocumentSignatureType.BINARY_DOCUMENT,
        subpacketCallback: Callback? = null
    ) = apply {
        val keyRingInfo = inspectKeyRing(signingKey, evaluationDate)
        if (userId != null && !keyRingInfo.isUserIdValid(userId)) {
            throw UnboundUserIdException(
                of(signingKey),
                userId.toString(),
                keyRingInfo.getLatestUserIdCertification(userId),
                keyRingInfo.getUserIdRevocation(userId))
        }

        val signingPubKeys = keyRingInfo.signingSubkeys
        if (signingPubKeys.isEmpty()) {
            throw UnacceptableSigningKeyException(of(signingKey))
        }

        for (signingPubKey in signingPubKeys) {
            val signingSecKey: PGPSecretKey =
                signingKey.getSecretKey(signingPubKey.keyID)
                    ?: throw MissingSecretKeyException(of(signingKey), signingPubKey.keyID)
            val signingSubkey: PGPPrivateKey = signingSecKey.unlock(signingKeyProtector)
            val hashAlgorithms =
                if (userId != null) keyRingInfo.getPreferredHashAlgorithms(userId)
                else keyRingInfo.getPreferredHashAlgorithms(signingPubKey.keyID)
            val hashAlgorithm: HashAlgorithm = negotiateHashAlgorithm(hashAlgorithms, getPolicy())
            addSigningMethod(
                signingKey, signingSubkey, hashAlgorithm, signatureType, true, subpacketCallback)
        }
    }

    /**
     * Create a detached signature using the signing key with the given keyId.
     *
     * @param signingKeyProtector decryptor to unlock the secret key
     * @param signingKey secret key ring
     * @param keyId keyId of the signing (sub-)key
     * @param signatureType signature type
     * @param subpacketsCallback callback to modify the signatures subpackets
     * @return builder
     * @throws PGPException if the secret key cannot be unlocked or if no signing method can be
     *   created.
     * @throws KeyException.UnacceptableSigningKeyException if the key ring does not carry any
     *   signing-capable subkeys
     * @throws KeyException.MissingSecretKeyException if the key ring does not contain the
     *   identified secret key
     */
    @Throws(KeyException::class, PGPException::class)
    @JvmOverloads
    fun addDetachedSignature(
        signingKeyProtector: SecretKeyRingProtector,
        signingKey: PGPSecretKeyRing,
        keyId: Long,
        signatureType: DocumentSignatureType = DocumentSignatureType.BINARY_DOCUMENT,
        subpacketsCallback: Callback? = null
    ) = apply {
        val keyRingInfo = inspectKeyRing(signingKey, evaluationDate)

        val signingPubKeys = keyRingInfo.signingSubkeys
        if (signingPubKeys.isEmpty()) {
            throw UnacceptableSigningKeyException(of(signingKey))
        }

        for (signingPubKey in signingPubKeys) {
            if (signingPubKey.keyID == keyId) {
                val signingSecKey: PGPSecretKey =
                    signingKey.getSecretKey(signingPubKey.keyID)
                        ?: throw MissingSecretKeyException(of(signingKey), signingPubKey.keyID)
                val signingSubkey: PGPPrivateKey = signingSecKey.unlock(signingKeyProtector)
                val hashAlgorithms = keyRingInfo.getPreferredHashAlgorithms(signingPubKey.keyID)
                val hashAlgorithm: HashAlgorithm =
                    negotiateHashAlgorithm(hashAlgorithms, getPolicy())
                addSigningMethod(
                    signingKey,
                    signingSubkey,
                    hashAlgorithm,
                    signatureType,
                    true,
                    subpacketsCallback)
                return this
            }
        }

        throw MissingSecretKeyException(of(signingKey), keyId)
    }

    private fun addSigningMethod(
        signingKey: PGPSecretKeyRing,
        signingSubkey: PGPPrivateKey,
        hashAlgorithm: HashAlgorithm,
        signatureType: DocumentSignatureType,
        detached: Boolean,
        subpacketCallback: Callback? = null
    ) {
        val signingKeyIdentifier = SubkeyIdentifier(signingKey, signingSubkey.keyID)
        val signingSecretKey: PGPSecretKey = signingKey.getSecretKey(signingSubkey.keyID)
        val publicKeyAlgorithm = requireFromId(signingSecretKey.publicKey.algorithm)
        val bitStrength = signingSecretKey.publicKey.bitStrength
        if (!getPolicy().publicKeyAlgorithmPolicy.isAcceptable(publicKeyAlgorithm, bitStrength)) {
            throw UnacceptableSigningKeyException(
                PublicKeyAlgorithmPolicyException(
                    of(signingKey), signingSecretKey.keyID, publicKeyAlgorithm, bitStrength))
        }

        val generator: PGPSignatureGenerator =
            createSignatureGenerator(
                signingSubkey,
                signingKey.getPublicKey(signingSubkey.keyID),
                hashAlgorithm,
                signatureType)

        // Subpackets
        val hashedSubpackets =
            SignatureSubpackets.createHashedSubpackets(signingSecretKey.publicKey)
        val unhashedSubpackets = SignatureSubpackets.createEmptySubpackets()
        if (subpacketCallback != null) {
            subpacketCallback.modifyHashedSubpackets(hashedSubpackets)
            subpacketCallback.modifyUnhashedSubpackets(unhashedSubpackets)
        }
        generator.setHashedSubpackets(SignatureSubpacketsHelper.toVector(hashedSubpackets))
        generator.setUnhashedSubpackets(SignatureSubpacketsHelper.toVector(unhashedSubpackets))

        val signingMethod =
            if (detached) SigningMethod.detachedSignature(generator, hashAlgorithm)
            else SigningMethod.inlineSignature(generator, hashAlgorithm)
        (signingMethods as MutableMap)[signingKeyIdentifier] = signingMethod
    }

    /**
     * Negotiate, which hash algorithm to use.
     *
     * This method gives the highest priority to the algorithm override, which can be set via
     * [.overrideHashAlgorithm]. After that, the signing keys hash algorithm preferences are
     * iterated to find the first acceptable algorithm. Lastly, should no acceptable algorithm be
     * found, the [Policies][Policy] default signature hash algorithm is used as a fallback.
     *
     * @param preferences preferences
     * @param policy policy
     * @return selected hash algorithm
     */
    private fun negotiateHashAlgorithm(
        preferences: Set<HashAlgorithm>,
        policy: Policy
    ): HashAlgorithm {
        return _hashAlgorithmOverride
            ?: negotiateSignatureHashAlgorithm(policy).negotiateHashAlgorithm(preferences)
    }

    @Throws(PGPException::class)
    private fun createSignatureGenerator(
        privateKey: PGPPrivateKey,
        publicKey: PGPPublicKey,
        hashAlgorithm: HashAlgorithm,
        signatureType: DocumentSignatureType
    ): PGPSignatureGenerator {
        return ImplementationFactory.getInstance()
            .getPGPContentSignerBuilder(
                privateKey.publicKeyPacket.algorithm, hashAlgorithm.algorithmId)
            .let { csb ->
                PGPSignatureGenerator(csb, publicKey).also {
                    it.init(signatureType.signatureType.code, privateKey)
                }
            }
    }

    companion object {
        @JvmStatic fun get() = SigningOptions()
    }

    /** A method of signing. */
    class SigningMethod
    private constructor(
        val signatureGenerator: PGPSignatureGenerator,
        val isDetached: Boolean,
        val hashAlgorithm: HashAlgorithm
    ) {
        companion object {

            /**
             * Inline-signature method. The resulting signature will be written into the message
             * itself, together with a one-pass-signature packet.
             *
             * @param signatureGenerator signature generator
             * @param hashAlgorithm hash algorithm used to generate the signature
             * @return inline signing method
             */
            @JvmStatic
            fun inlineSignature(
                signatureGenerator: PGPSignatureGenerator,
                hashAlgorithm: HashAlgorithm
            ) = SigningMethod(signatureGenerator, false, hashAlgorithm)

            /**
             * Detached signing method. The resulting signature will not be added to the message,
             * and instead can be distributed separately to the signed message.
             *
             * @param signatureGenerator signature generator
             * @param hashAlgorithm hash algorithm used to generate the signature
             * @return detached signing method
             */
            @JvmStatic
            fun detachedSignature(
                signatureGenerator: PGPSignatureGenerator,
                hashAlgorithm: HashAlgorithm
            ) = SigningMethod(signatureGenerator, true, hashAlgorithm)
        }
    }
}
