// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.consumer

import java.io.InputStream
import java.util.*
import openpgp.openPgpKeyId
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.bouncycastle.extensions.getPublicKey
import org.pgpainless.bouncycastle.extensions.issuerKeyId
import org.pgpainless.exception.SignatureValidationException
import org.pgpainless.key.util.KeyRingUtils
import org.pgpainless.policy.Policy
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil
import org.slf4j.LoggerFactory

/**
 * A collection of static methods that validate signing certificates (public keys) and verify
 * signature correctness.
 */
class CertificateValidator {

    companion object {

        @JvmStatic private val LOGGER = LoggerFactory.getLogger(CertificateValidator::class.java)

        /**
         * Check if the signing key was eligible to create the provided signature.
         *
         * That entails:
         * - Check, if the primary key is being revoked via key-revocation signatures.
         * - Check, if the keys user-ids are revoked or not bound.
         * - Check, if the signing subkey is revoked or expired.
         * - Check, if the signing key is not capable of signing
         *
         * @param signature signature
         * @param signingKeyRing signing key ring
         * @param policy validation policy
         * @return true if the signing key was eligible to create the signature
         * @throws SignatureValidationException in case of a validation constraint violation
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun validateCertificate(
            signature: PGPSignature,
            signingKeyRing: PGPPublicKeyRing,
            policy: Policy = PGPainless.getPolicy()
        ): Boolean {
            val signingSubkey: PGPPublicKey =
                signingKeyRing.getPublicKey(signature.issuerKeyId)
                    ?: throw SignatureValidationException(
                        "Provided key ring does not contain a subkey with id ${signature.issuerKeyId.openPgpKeyId()}.")
            val primaryKey = signingKeyRing.publicKey!!
            val directKeyAndRevSigs = mutableListOf<PGPSignature>()
            val rejections = mutableMapOf<PGPSignature, Exception>()
            // revocations
            primaryKey
                .getSignaturesOfType(SignatureType.KEY_REVOCATION.code)
                .asSequence()
                .filter {
                    it.issuerKeyId == primaryKey.keyID
                } // We do not support external rev keys
                .forEach {
                    try {
                        if (SignatureVerifier.verifyKeyRevocationSignature(
                            it, primaryKey, policy, signature.creationTime)) {
                            directKeyAndRevSigs.add(it)
                        }
                    } catch (e: SignatureValidationException) {
                        rejections[it] = e
                        LOGGER.debug("Rejecting key revocation signature: ${e.message}", e)
                    }
                }

            // direct-key sigs
            primaryKey
                .getSignaturesOfType(SignatureType.DIRECT_KEY.code)
                .asSequence()
                .filter { it.issuerKeyId == primaryKey.keyID }
                .forEach {
                    try {
                        if (SignatureVerifier.verifyDirectKeySignature(
                            it, primaryKey, policy, signature.creationTime)) {
                            directKeyAndRevSigs.add(it)
                        }
                    } catch (e: SignatureValidationException) {
                        rejections[it] = e
                        LOGGER.debug("Rejecting key signature: ${e.message}, e")
                    }
                }

            directKeyAndRevSigs.sortWith(
                SignatureValidityComparator(SignatureCreationDateComparator.Order.NEW_TO_OLD))
            if (directKeyAndRevSigs.isNotEmpty()) {
                if (directKeyAndRevSigs[0].signatureType == SignatureType.KEY_REVOCATION.code) {
                    throw SignatureValidationException("Primary key has been revoked.")
                }
            }

            // UserID signatures
            val userIdSignatures = mutableMapOf<String, List<PGPSignature>>()
            KeyRingUtils.getUserIdsIgnoringInvalidUTF8(primaryKey).forEach { userId ->
                buildList<PGPSignature> {
                        primaryKey
                            .getSignaturesForID(userId)
                            .asSequence()
                            .filter { it.issuerKeyId == primaryKey.keyID }
                            .forEach { uidSig ->
                                try {
                                    if (SignatureVerifier.verifySignatureOverUserId(
                                        userId,
                                        uidSig,
                                        primaryKey,
                                        policy,
                                        signature.creationTime)) {
                                        add(uidSig)
                                    }
                                } catch (e: SignatureValidationException) {
                                    rejections[uidSig] = e
                                    LOGGER.debug("Rejecting user-id signature: ${e.message}", e)
                                }
                            }
                    }
                    .sortedWith(
                        SignatureValidityComparator(
                            SignatureCreationDateComparator.Order.NEW_TO_OLD))
                    .let { userIdSignatures[userId] = it }
            }

            val hasAnyUserIds = userIdSignatures.isNotEmpty()
            val isAnyUserIdValid =
                userIdSignatures.any { entry ->
                    entry.value.isNotEmpty() &&
                        entry.value[0].signatureType != SignatureType.CERTIFICATION_REVOCATION.code
                }

            if (hasAnyUserIds && !isAnyUserIdValid) {
                throw SignatureValidationException("No valid user-id found.", rejections)
            }

            // Specific signer user-id
            if (policy.signerUserIdValidationLevel == Policy.SignerUserIdValidationLevel.STRICT) {
                SignatureSubpacketsUtil.getSignerUserID(signature)?.let {
                    if (userIdSignatures[it.id] == null || userIdSignatures[it.id]!!.isEmpty()) {
                        throw SignatureValidationException(
                            "Signature was allegedly made by user-id '${it.id}'," +
                                " but we have no valid signatures for that on the certificate.")
                    }

                    if (userIdSignatures[it.id]!![0].signatureType ==
                        SignatureType.CERTIFICATION_REVOCATION.code) {
                        throw SignatureValidationException(
                            "Signature was made with user-id '${it.id}' which is revoked.")
                    }
                }
            }

            if (signingSubkey.keyID == primaryKey.keyID) { // signing key is primary key
                if (directKeyAndRevSigs.isNotEmpty()) {
                    val directKeySig = directKeyAndRevSigs[0]!!
                    val flags = SignatureSubpacketsUtil.getKeyFlags(directKeySig)
                    if (flags != null && KeyFlag.hasKeyFlag(flags.flags, KeyFlag.SIGN_DATA)) {
                        return true
                    }
                }
                // Reject sigs by non-signing keys
                if (userIdSignatures.none { (_, sigs) ->
                    sigs.any {
                        SignatureSubpacketsUtil.getKeyFlags(it)?.let { f ->
                            KeyFlag.hasKeyFlag(f.flags, KeyFlag.SIGN_DATA)
                        } == true
                    }
                }) {
                    throw SignatureValidationException(
                        "Signature was generated by non-signing key.")
                }
            } else { // signing key is subkey
                val subkeySigs = mutableListOf<PGPSignature>()
                signingSubkey
                    .getSignaturesOfType(SignatureType.SUBKEY_REVOCATION.code)
                    .asSequence()
                    .filter { it.issuerKeyId == primaryKey.keyID }
                    .forEach {
                        try {
                            if (SignatureVerifier.verifySubkeyBindingRevocation(
                                it, primaryKey, signingSubkey, policy, signature.creationTime)) {
                                subkeySigs.add(it)
                            }
                        } catch (e: SignatureValidationException) {
                            rejections[it] = e
                            LOGGER.debug("Rejecting subkey revocation signature: ${e.message}", e)
                        }
                    }

                signingSubkey
                    .getSignaturesOfType(SignatureType.SUBKEY_BINDING.code)
                    .asSequence()
                    .forEach {
                        try {
                            if (SignatureVerifier.verifySubkeyBindingSignature(
                                it, primaryKey, signingSubkey, policy, signature.creationTime)) {
                                subkeySigs.add(it)
                            }
                        } catch (e: SignatureValidationException) {
                            rejections[it] = e
                            LOGGER.debug("Rejecting subkey binding signature: ${e.message}", e)
                        }
                    }

                subkeySigs.sortWith(
                    SignatureValidityComparator(SignatureCreationDateComparator.Order.NEW_TO_OLD))
                if (subkeySigs.isEmpty()) {
                    throw SignatureValidationException("Subkey is not bound.", rejections)
                }

                if (subkeySigs[0].signatureType == SignatureType.SUBKEY_REVOCATION.code) {
                    throw SignatureValidationException("Subkey is revoked.")
                }

                val keyFlags = SignatureSubpacketsUtil.getKeyFlags(subkeySigs[0])
                if (keyFlags == null || !KeyFlag.hasKeyFlag(keyFlags.flags, KeyFlag.SIGN_DATA)) {
                    throw SignatureValidationException(
                        "Signature was made by key which is not capable of signing (no keyflag).")
                }
            }
            return true
        }

        /**
         * Validate the given signing key and then verify the given signature while parsing out the
         * signed data. Uninitialized means that no signed data has been read and the hash
         * generators state has not yet been updated.
         *
         * @param signature uninitialized signature
         * @param signedData input stream containing signed data
         * @param signingKeyRing key ring containing signing key
         * @param policy validation policy
         * @param validationDate date of validation
         * @return true if the signature is valid, false otherwise
         * @throws SignatureValidationException for validation constraint violations
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun validateCertificateAndVerifyUninitializedSignature(
            signature: PGPSignature,
            signedData: InputStream,
            signingKeyRing: PGPPublicKeyRing,
            policy: Policy,
            referenceTime: Date = signature.creationTime
        ): Boolean {
            return validateCertificate(signature, signingKeyRing, policy) &&
                SignatureVerifier.verifyUninitializedSignature(
                    signature,
                    signedData,
                    signingKeyRing.getPublicKey(signature.issuerKeyId)!!,
                    policy,
                    referenceTime)
        }

        /**
         * Validate the signing key and the given initialized signature. Initialized means that the
         * signatures hash generator has already been updated by reading the signed data completely.
         *
         * @param signature initialized signature
         * @param verificationKeys key ring containing the verification key
         * @param policy validation policy
         * @return true if the signature is valid, false otherwise
         * @throws SignatureValidationException in case of a validation constraint violation
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun validateCertificateAndVerifyInitializedSignature(
            signature: PGPSignature,
            verificationKeys: PGPPublicKeyRing,
            policy: Policy
        ): Boolean {
            return validateCertificate(signature, verificationKeys, policy) &&
                SignatureVerifier.verifyInitializedSignature(
                    signature,
                    verificationKeys.getPublicKey(signature.issuerKeyId),
                    policy,
                    signature.creationTime)
        }

        /**
         * Validate the signing key certificate and the given [OnePassSignatureCheck].
         *
         * @param onePassSignature corresponding one-pass-signature
         * @param policy policy
         * @return true if the certificate is valid and the signature is correct, false otherwise.
         * @throws SignatureValidationException in case of a validation error
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun validateCertificateAndVerifyOnePassSignature(
            onePassSignature: OnePassSignatureCheck,
            policy: Policy
        ): Boolean {
            return validateCertificate(
                onePassSignature.signature!!,
                onePassSignature.verificationKeys.pgpPublicKeyRing,
                policy) &&
                SignatureVerifier.verifyOnePassSignature(
                    onePassSignature.signature!!,
                    onePassSignature.verificationKeys.pgpKeyRing.getPublicKey(
                        onePassSignature.signature!!.issuerKeyId),
                    onePassSignature,
                    policy)
        }
    }
}
