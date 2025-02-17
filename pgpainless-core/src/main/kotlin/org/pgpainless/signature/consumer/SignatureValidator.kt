// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.consumer

import java.lang.Exception
import java.util.Date
import openpgp.formatUTC
import openpgp.openPgpKeyId
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.algorithm.SignatureSubpacket
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.bouncycastle.extensions.fingerprint
import org.pgpainless.bouncycastle.extensions.isHardRevocation
import org.pgpainless.bouncycastle.extensions.isOfType
import org.pgpainless.bouncycastle.extensions.publicKeyAlgorithm
import org.pgpainless.bouncycastle.extensions.signatureExpirationDate
import org.pgpainless.bouncycastle.extensions.signatureHashAlgorithm
import org.pgpainless.exception.SignatureValidationException
import org.pgpainless.implementation.ImplementationFactory
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.policy.Policy
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil
import org.pgpainless.util.NotationRegistry

abstract class SignatureValidator {

    @Throws(SignatureValidationException::class) abstract fun verify(signature: PGPSignature)

    companion object {

        /**
         * Check, whether there is the possibility that the given signature was created by the given
         * key. [verify] throws a [SignatureValidationException] if we can say with certainty that
         * the signature was not created by the given key (e.g. if the sig carries another issuer,
         * issuer fingerprint packet).
         *
         * If there is no information found in the signature about who created it (no issuer, no
         * fingerprint), [verify] will simply return since it is plausible that the given key
         * created the sig.
         *
         * @param signingKey signing key
         * @return validator that throws a [SignatureValidationException] if the signature was not
         *   possibly made by the given key.
         */
        @JvmStatic
        fun wasPossiblyMadeByKey(signingKey: PGPPublicKey): SignatureValidator {
            return object : SignatureValidator() {
                override fun verify(signature: PGPSignature) {
                    val signingKeyFingerprint = OpenPgpFingerprint.of(signingKey)
                    val issuer = SignatureSubpacketsUtil.getIssuerKeyIdAsLong(signature)

                    if (issuer != null) {
                        if (issuer != signingKey.keyID) {
                            throw SignatureValidationException(
                                "Signature was not created by" +
                                    " $signingKeyFingerprint (signature issuer: ${issuer.openPgpKeyId()})")
                        }
                    }

                    if (signature.fingerprint != null &&
                        signature.fingerprint != signingKeyFingerprint) {
                        throw SignatureValidationException(
                            "Signature was not created by" +
                                " $signingKeyFingerprint (signature fingerprint: ${signature.fingerprint})")
                    }
                }

                // No issuer information found, so we cannot rule out that we did not create the sig
            }
        }

        /**
         * Verify that a subkey binding signature - if the subkey is signing-capable - contains a
         * valid primary key binding signature.
         *
         * @param primaryKey primary key
         * @param subkey subkey
         * @param policy policy
         * @param referenceDate reference date for signature verification
         * @return validator
         */
        @JvmStatic
        fun hasValidPrimaryKeyBindingSignatureIfRequired(
            primaryKey: PGPPublicKey,
            subkey: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): SignatureValidator {
            return object : SignatureValidator() {
                override fun verify(signature: PGPSignature) {
                    if (!signature.publicKeyAlgorithm.isSigningCapable()) {
                        // subkey is not signing capable -> No need to process embedded signatures
                        return
                    }

                    // Make sure we have key flags
                    SignatureSubpacketsUtil.getKeyFlags(signature)?.let {
                        if (!KeyFlag.hasKeyFlag(it.flags, KeyFlag.SIGN_DATA) &&
                            !KeyFlag.hasKeyFlag(it.flags, KeyFlag.CERTIFY_OTHER)) {
                            return
                        }
                    }
                        ?: return

                    try {
                        val embeddedSignatures =
                            SignatureSubpacketsUtil.getEmbeddedSignature(signature)
                        if (embeddedSignatures.isEmpty) {
                            throw SignatureValidationException(
                                "Missing primary key binding" +
                                    " signature on signing capable subkey ${subkey.keyID.openPgpKeyId()}",
                                mapOf())
                        }

                        val rejectedEmbeddedSignatures = mutableMapOf<PGPSignature, Exception>()
                        if (!embeddedSignatures.any { embedded ->
                            if (embedded.isOfType(SignatureType.PRIMARYKEY_BINDING)) {
                                try {
                                    signatureStructureIsAcceptable(subkey, policy).verify(embedded)
                                    signatureIsEffective(referenceTime).verify(embedded)
                                    correctPrimaryKeyBindingSignature(primaryKey, subkey)
                                        .verify(embedded)
                                    return@any true
                                } catch (e: SignatureValidationException) {
                                    rejectedEmbeddedSignatures[embedded] = e
                                }
                            }
                            false
                        }) {
                            throw SignatureValidationException(
                                "Missing primary key binding signature on signing capable subkey ${subkey.keyID.openPgpKeyId()}",
                                rejectedEmbeddedSignatures)
                        }
                    } catch (e: PGPException) {
                        throw SignatureValidationException(
                            "Cannot process list of embedded signatures.", e)
                    }
                }
            }
        }

        /**
         * Verify that a signature has an acceptable structure.
         *
         * @param signingKey signing key
         * @param policy policy
         * @return validator
         */
        @JvmStatic
        fun signatureStructureIsAcceptable(
            signingKey: PGPPublicKey,
            policy: Policy
        ): SignatureValidator {
            return object : SignatureValidator() {
                override fun verify(signature: PGPSignature) {
                    signatureIsNotMalformed(signingKey).verify(signature)
                    if (signature.version >= 4) {
                        signatureDoesNotHaveCriticalUnknownNotations(policy.notationRegistry)
                            .verify(signature)
                        signatureDoesNotHaveCriticalUnknownSubpackets().verify(signature)
                    }
                    signatureUsesAcceptableHashAlgorithm(policy).verify(signature)
                    signatureUsesAcceptablePublicKeyAlgorithm(policy, signingKey).verify(signature)
                }
            }
        }

        /**
         * Verify that a signature was made using an acceptable [PublicKeyAlgorithm].
         *
         * @param policy policy
         * @param signingKey signing key
         * @return validator
         */
        @JvmStatic
        fun signatureUsesAcceptablePublicKeyAlgorithm(
            policy: Policy,
            signingKey: PGPPublicKey
        ): SignatureValidator {
            return object : SignatureValidator() {
                override fun verify(signature: PGPSignature) {
                    if (signingKey.bitStrength == -1) {
                        throw SignatureValidationException(
                            "Cannot determine bit strength of signing key.")
                    }
                    if (!policy.publicKeyAlgorithmPolicy.isAcceptable(
                        signingKey.publicKeyAlgorithm, signingKey.bitStrength)) {
                        throw SignatureValidationException(
                            "Signature was made using unacceptable key. " +
                                "${signingKey.publicKeyAlgorithm} (${signingKey.bitStrength} bits) is " +
                                "not acceptable according to the public key algorithm policy.")
                    }
                }
            }
        }

        @JvmStatic
        fun signatureUsesAcceptableHashAlgorithm(policy: Policy): SignatureValidator {
            return object : SignatureValidator() {
                override fun verify(signature: PGPSignature) {
                    try {
                        val algorithmPolicy = getHashAlgorithmPolicyForSignature(signature, policy)
                        if (!algorithmPolicy.isAcceptable(
                            signature.signatureHashAlgorithm, signature.creationTime)) {
                            throw SignatureValidationException(
                                "Signature uses unacceptable" +
                                    " hash algorithm ${signature.signatureHashAlgorithm}" +
                                    " (Signature creation time: ${signature.creationTime.formatUTC()})")
                        }
                    } catch (e: NoSuchElementException) {
                        throw SignatureValidationException(
                            "Signature uses unknown hash" + " algorithm ${signature.hashAlgorithm}")
                    }
                }
            }
        }

        /**
         * Return the applicable [Policy.HashAlgorithmPolicy] for the given [PGPSignature].
         * Revocation signatures are being policed using a different policy than non-revocation
         * signatures.
         *
         * @param signature signature
         * @param policy revocation policy for revocation sigs, normal policy for non-rev sigs
         * @return policy
         */
        @JvmStatic
        private fun getHashAlgorithmPolicyForSignature(
            signature: PGPSignature,
            policy: Policy
        ): Policy.HashAlgorithmPolicy {
            return when (SignatureType.fromCode(signature.signatureType)) {
                null -> policy.certificationSignatureHashAlgorithmPolicy
                SignatureType.CERTIFICATION_REVOCATION,
                SignatureType.KEY_REVOCATION,
                SignatureType.SUBKEY_REVOCATION -> policy.revocationSignatureHashAlgorithmPolicy
                SignatureType.GENERIC_CERTIFICATION,
                SignatureType.NO_CERTIFICATION,
                SignatureType.CASUAL_CERTIFICATION,
                SignatureType.POSITIVE_CERTIFICATION,
                SignatureType.DIRECT_KEY,
                SignatureType.SUBKEY_BINDING,
                SignatureType.PRIMARYKEY_BINDING -> policy.certificationSignatureHashAlgorithmPolicy
                else -> policy.dataSignatureHashAlgorithmPolicy
            }
        }

        /**
         * Verify that a signature does not carry critical unknown notations.
         *
         * @param registry notation registry of known notations
         * @return validator
         */
        @JvmStatic
        fun signatureDoesNotHaveCriticalUnknownNotations(
            registry: NotationRegistry
        ): SignatureValidator {
            return object : SignatureValidator() {
                override fun verify(signature: PGPSignature) {
                    SignatureSubpacketsUtil.getHashedNotationData(signature)
                        .filter { it.isCritical && !registry.isKnownNotation(it.notationName) }
                        .forEach {
                            throw SignatureValidationException(
                                "Signature contains unknown critical notation '${it.notationName}' in its hashed area.")
                        }
                }
            }
        }

        /**
         * Verify that a signature does not contain critical unknown subpackets.
         *
         * @return validator
         */
        @JvmStatic
        fun signatureDoesNotHaveCriticalUnknownSubpackets(): SignatureValidator {
            return object : SignatureValidator() {
                override fun verify(signature: PGPSignature) {
                    signature.hashedSubPackets.criticalTags.forEach {
                        try {
                            SignatureSubpacket.requireFromCode(it)
                        } catch (e: NoSuchElementException) {
                            throw SignatureValidationException(
                                "Signature contains unknown critical subpacket of type 0x${Integer.toHexString(it)}")
                        }
                    }
                }
            }
        }

        /**
         * Verify that a signature is effective at the given reference date.
         *
         * @param referenceTime reference date for signature verification
         * @return validator
         */
        @JvmStatic
        @JvmOverloads
        fun signatureIsEffective(referenceTime: Date = Date()): SignatureValidator {
            return object : SignatureValidator() {
                override fun verify(signature: PGPSignature) {
                    signatureIsAlreadyEffective(referenceTime).verify(signature)
                    signatureIsNotYetExpired(referenceTime).verify(signature)
                }
            }
        }

        /**
         * Verify that a signature was created prior to the given reference date.
         *
         * @param referenceTime reference date for signature verification
         * @return validator
         */
        @JvmStatic
        fun signatureIsAlreadyEffective(referenceTime: Date): SignatureValidator {
            return object : SignatureValidator() {
                override fun verify(signature: PGPSignature) {
                    if (signature.isHardRevocation) {
                        return
                    }
                    if (signature.creationTime > referenceTime) {
                        throw SignatureValidationException(
                            "Signature was created at ${signature.creationTime.formatUTC()} and" +
                                " is therefore not yet valid at ${referenceTime.formatUTC()}")
                    }
                }
            }
        }

        /**
         * Verify that a signature is not yet expired.
         *
         * @param referenceTime reference date for signature verification
         * @return validator
         */
        @JvmStatic
        fun signatureIsNotYetExpired(referenceTime: Date): SignatureValidator {
            return object : SignatureValidator() {
                override fun verify(signature: PGPSignature) {
                    if (signature.isHardRevocation) {
                        return
                    }
                    val expirationDate = signature.signatureExpirationDate
                    if (expirationDate != null && expirationDate < referenceTime) {
                        throw SignatureValidationException(
                            "Signature is already expired " +
                                "(expiration: ${expirationDate.formatUTC()}," +
                                " validation: ${referenceTime.formatUTC()})")
                    }
                }
            }
        }

        /**
         * Verify that a signature is not malformed. A signature is malformed if it has no hashed
         * creation time subpacket, it predates the creation time of the signing key, or it predates
         * the creation date of the signing key binding signature.
         *
         * @param signingKey signing key
         * @return validator
         */
        @JvmStatic
        fun signatureIsNotMalformed(signingKey: PGPPublicKey): SignatureValidator {
            return object : SignatureValidator() {
                override fun verify(signature: PGPSignature) {
                    if (signature.version >= 4) {
                        signatureHasHashedCreationTime().verify(signature)
                    }
                    signatureDoesNotPredateSigningKey(signingKey).verify(signature)
                    if (!signature.isOfType(SignatureType.PRIMARYKEY_BINDING)) {
                        signatureDoesNotPredateSigningKeyBindingDate(signingKey).verify(signature)
                    }
                }
            }
        }

        @JvmStatic
        fun signatureDoesNotPredateSignee(signee: PGPPublicKey): SignatureValidator {
            return signatureDoesNotPredateKeyCreation(signee)
        }

        /**
         * Verify that a signature does not predate the creation time of the signing key.
         *
         * @param key signing key
         * @return validator
         */
        @JvmStatic
        fun signatureDoesNotPredateSigningKey(signingKey: PGPPublicKey): SignatureValidator {
            return signatureDoesNotPredateKeyCreation(signingKey)
        }

        /**
         * Verify that a signature does not predate the creation time of the given key.
         *
         * @param key key
         * @return validator
         */
        @JvmStatic
        fun signatureDoesNotPredateKeyCreation(key: PGPPublicKey): SignatureValidator {
            return object : SignatureValidator() {
                override fun verify(signature: PGPSignature) {
                    if (key.creationTime > signature.creationTime) {
                        throw SignatureValidationException(
                            "Signature predates key" +
                                " (key creation: ${key.creationTime.formatUTC()}," +
                                " signature creation: ${signature.creationTime.formatUTC()})")
                    }
                }
            }
        }

        /**
         * Verify that a signature has a hashed creation time subpacket.
         *
         * @return validator
         */
        @JvmStatic
        fun signatureHasHashedCreationTime(): SignatureValidator {
            return object : SignatureValidator() {
                override fun verify(signature: PGPSignature) {
                    if (SignatureSubpacketsUtil.getSignatureCreationTime(signature) == null) {
                        throw SignatureValidationException(
                            "Malformed signature." +
                                "Signature has no signature creation time subpacket in its hashed area.")
                    }
                }
            }
        }

        /**
         * Verify that a signature does not predate the binding date of the signing key.
         *
         * @param signingKey signing key
         * @return validator
         */
        @JvmStatic
        fun signatureDoesNotPredateSigningKeyBindingDate(
            signingKey: PGPPublicKey
        ): SignatureValidator {
            return object : SignatureValidator() {
                override fun verify(signature: PGPSignature) {
                    if (signingKey.isMasterKey) {
                        return
                    }
                    if (signingKey
                        .getSignaturesOfType(SignatureType.SUBKEY_BINDING.code)
                        .asSequence()
                        .map {
                            if (signature.creationTime < it.creationTime) {
                                throw SignatureValidationException(
                                    "Signature was created " +
                                        "before the signing key was bound to the certificate.")
                            }
                        }
                        .none()) {
                        throw SignatureValidationException(
                            "Signing subkey does not have a subkey binding signature.")
                    }
                }
            }
        }

        /**
         * Verify that a subkey binding signature is correct.
         *
         * @param primaryKey primary key
         * @param subkey subkey
         * @return validator
         */
        @JvmStatic
        fun correctSubkeyBindingSignature(
            primaryKey: PGPPublicKey,
            subkey: PGPPublicKey
        ): SignatureValidator {
            return object : SignatureValidator() {
                override fun verify(signature: PGPSignature) {
                    if (primaryKey.keyID == subkey.keyID) {
                        throw SignatureValidationException("Primary key cannot be its own subkey.")
                    }
                    try {
                        signature.init(
                            ImplementationFactory.getInstance().pgpContentVerifierBuilderProvider,
                            primaryKey)
                        if (!signature.verifyCertification(primaryKey, subkey)) {
                            throw SignatureValidationException("Signature is not correct.")
                        }
                    } catch (e: PGPException) {
                        throw SignatureValidationException(
                            "Cannot verify subkey binding signature correctness", e)
                    } catch (e: ClassCastException) {
                        throw SignatureValidationException(
                            "Cannot verify subkey binding signature correctness", e)
                    }
                }
            }
        }

        /**
         * Verify that a primary key binding signature is correct.
         *
         * @param primaryKey primary key
         * @param subkey subkey
         * @return validator
         */
        @JvmStatic
        fun correctPrimaryKeyBindingSignature(
            primaryKey: PGPPublicKey,
            subkey: PGPPublicKey
        ): SignatureValidator {
            return object : SignatureValidator() {
                override fun verify(signature: PGPSignature) {
                    if (primaryKey.keyID == subkey.keyID) {
                        throw SignatureValidationException("Primary key cannot be its own subkey.")
                    }
                    try {
                        signature.init(
                            ImplementationFactory.getInstance().pgpContentVerifierBuilderProvider,
                            subkey)
                        if (!signature.verifyCertification(primaryKey, subkey)) {
                            throw SignatureValidationException(
                                "Primary Key Binding Signature is not correct.")
                        }
                    } catch (e: PGPException) {
                        throw SignatureValidationException(
                            "Cannot verify primary key binding signature correctness", e)
                    } catch (e: ClassCastException) {
                        throw SignatureValidationException(
                            "Cannot verify primary key binding signature correctness", e)
                    }
                }
            }
        }

        /**
         * Verify that a direct-key signature is correct.
         *
         * @param signingKey signing key
         * @param signedKey signed key
         * @return validator
         */
        @JvmStatic
        fun correctSignatureOverKey(
            signingKey: PGPPublicKey,
            signedKey: PGPPublicKey
        ): SignatureValidator {
            return object : SignatureValidator() {
                override fun verify(signature: PGPSignature) {
                    try {
                        signature.init(
                            ImplementationFactory.getInstance().pgpContentVerifierBuilderProvider,
                            signingKey)
                        val valid =
                            if (signingKey.keyID == signedKey.keyID ||
                                signature.isOfType(SignatureType.DIRECT_KEY)) {
                                signature.verifyCertification(signedKey)
                            } else {
                                signature.verifyCertification(signingKey, signedKey)
                            }
                        if (!valid) {
                            throw SignatureValidationException("Signature is not correct.")
                        }
                    } catch (e: PGPException) {
                        throw SignatureValidationException(
                            "Cannot verify direct-key signature correctness", e)
                    } catch (e: ClassCastException) {
                        throw SignatureValidationException(
                            "Cannot verify direct-key signature correctness", e)
                    }
                }
            }
        }

        @JvmStatic
        fun signatureIsCertification(): SignatureValidator {
            return signatureIsOfType(
                SignatureType.POSITIVE_CERTIFICATION,
                SignatureType.CASUAL_CERTIFICATION,
                SignatureType.GENERIC_CERTIFICATION,
                SignatureType.NO_CERTIFICATION)
        }

        /**
         * Verify that a signature type equals one of the given [SignatureType].
         *
         * @param signatureType one or more signature types
         * @return validator
         */
        @JvmStatic
        fun signatureIsOfType(vararg signatureType: SignatureType): SignatureValidator {
            return object : SignatureValidator() {
                override fun verify(signature: PGPSignature) {
                    if (signatureType.none { signature.isOfType(it) }) {
                        throw SignatureValidationException(
                            "Signature is of type" +
                                " ${SignatureType.fromCode(signature.signatureType) ?:
                                ("0x" + signature.signatureType.toString(16))}, " +
                                "while only ${signatureType.contentToString()} are allowed here.")
                    }
                }
            }
        }

        /**
         * Verify that a signature over a user-id is correct.
         *
         * @param userId user-id
         * @param certifiedKey key carrying the user-id
         * @param certifyingKey key that created the signature.
         * @return validator
         */
        @JvmStatic
        fun correctSignatureOverUserId(
            userId: CharSequence,
            certifiedKey: PGPPublicKey,
            certifyingKey: PGPPublicKey
        ): SignatureValidator {
            return object : SignatureValidator() {
                override fun verify(signature: PGPSignature) {
                    try {
                        signature.init(
                            ImplementationFactory.getInstance().pgpContentVerifierBuilderProvider,
                            certifyingKey)
                        if (!signature.verifyCertification(userId.toString(), certifiedKey)) {
                            throw SignatureValidationException(
                                "Signature over user-id '$userId' is not valid.")
                        }
                    } catch (e: PGPException) {
                        throw SignatureValidationException(
                            "Cannot verify signature over user-id '$userId'.", e)
                    } catch (e: ClassCastException) {
                        throw SignatureValidationException(
                            "Cannot verify signature over user-id '$userId'.", e)
                    }
                }
            }
        }

        /**
         * Verify that a signature over a user-attribute packet is correct.
         *
         * @param userAttributes user attributes
         * @param certifiedKey key carrying the user-attributes
         * @param certifyingKey key that created the certification signature
         * @return validator
         */
        @JvmStatic
        fun correctSignatureOverUserAttributes(
            userAttributes: PGPUserAttributeSubpacketVector,
            certifiedKey: PGPPublicKey,
            certifyingKey: PGPPublicKey
        ): SignatureValidator {
            return object : SignatureValidator() {
                override fun verify(signature: PGPSignature) {
                    try {
                        signature.init(
                            ImplementationFactory.getInstance().pgpContentVerifierBuilderProvider,
                            certifyingKey)
                        if (!signature.verifyCertification(userAttributes, certifiedKey)) {
                            throw SignatureValidationException(
                                "Signature over user-attributes is not correct.")
                        }
                    } catch (e: PGPException) {
                        throw SignatureValidationException(
                            "Cannot verify signature over user-attribute vector.", e)
                    } catch (e: ClassCastException) {
                        throw SignatureValidationException(
                            "Cannot verify signature over user-attribute vector.", e)
                    }
                }
            }
        }

        @JvmStatic
        fun signatureWasCreatedInBounds(notBefore: Date?, notAfter: Date?): SignatureValidator {
            return object : SignatureValidator() {
                override fun verify(signature: PGPSignature) {
                    val timestamp = signature.creationTime
                    if (notBefore != null && timestamp < notBefore) {
                        throw SignatureValidationException(
                            "Signature was made before the earliest allowed signature creation time." +
                                " Created: ${timestamp.formatUTC()}," +
                                " earliest allowed: ${notBefore.formatUTC()}")
                    }
                    if (notAfter != null && timestamp > notAfter) {
                        throw SignatureValidationException(
                            "Signature was made after the latest allowed signature creation time." +
                                " Created: ${timestamp.formatUTC()}," +
                                " latest allowed: ${notAfter.formatUTC()}")
                    }
                }
            }
        }
    }
}
