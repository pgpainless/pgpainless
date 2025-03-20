// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.consumer

import java.io.IOException
import java.io.InputStream
import java.util.*
import openpgp.openPgpKeyId
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector
import org.bouncycastle.openpgp.api.OpenPGPImplementation
import org.pgpainless.algorithm.SignatureType
import org.pgpainless.exception.SignatureValidationException
import org.pgpainless.policy.Policy
import org.pgpainless.signature.consumer.SignatureValidator.Companion.correctSignatureOverKey
import org.pgpainless.signature.consumer.SignatureValidator.Companion.correctSignatureOverUserAttributes
import org.pgpainless.signature.consumer.SignatureValidator.Companion.correctSignatureOverUserId
import org.pgpainless.signature.consumer.SignatureValidator.Companion.correctSubkeyBindingSignature
import org.pgpainless.signature.consumer.SignatureValidator.Companion.hasValidPrimaryKeyBindingSignatureIfRequired
import org.pgpainless.signature.consumer.SignatureValidator.Companion.signatureDoesNotPredateSignee
import org.pgpainless.signature.consumer.SignatureValidator.Companion.signatureIsCertification
import org.pgpainless.signature.consumer.SignatureValidator.Companion.signatureIsEffective
import org.pgpainless.signature.consumer.SignatureValidator.Companion.signatureIsOfType
import org.pgpainless.signature.consumer.SignatureValidator.Companion.signatureStructureIsAcceptable
import org.pgpainless.signature.consumer.SignatureValidator.Companion.wasPossiblyMadeByKey

/**
 * Collection of static methods for signature verification. Signature verification entails
 * validation of certain criteria (see [SignatureValidator]), as well as cryptographic verification
 * of signature correctness.
 */
class SignatureVerifier {

    companion object {

        /**
         * Verify a signature (certification or revocation) over a user-id.
         *
         * @param userId user-id
         * @param signature certification signature
         * @param signingKey key that created the certification
         * @param keyWithUserId key carrying the user-id
         * @param policy policy
         * @param referenceTime reference date for signature verification
         * @return true if signature verification is successful
         * @throws SignatureValidationException if signature verification fails for some reason
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun verifySignatureOverUserId(
            userId: CharSequence,
            signature: PGPSignature,
            signingKey: PGPPublicKey,
            keyWithUserId: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): Boolean {
            val type = SignatureType.fromCode(signature.signatureType)
            return when (type) {
                SignatureType.GENERIC_CERTIFICATION,
                SignatureType.NO_CERTIFICATION,
                SignatureType.CASUAL_CERTIFICATION,
                SignatureType.POSITIVE_CERTIFICATION,
                null ->
                    verifyUserIdCertification(
                        userId, signature, signingKey, keyWithUserId, policy, referenceTime)
                SignatureType.CERTIFICATION_REVOCATION ->
                    verifyUserIdRevocation(
                        userId, signature, signingKey, keyWithUserId, policy, referenceTime)
                else ->
                    throw SignatureValidationException(
                        "Signature is not a valid user-id certification/revocation signature: $type")
            }
        }

        /**
         * Verify a certification self-signature over a user-id.
         *
         * @param userId user-id
         * @param signature certification signature
         * @param primaryKey primary key
         * @param policy policy
         * @param referenceTime reference date for signature verification
         * @return true if the self-signature is verified successfully
         * @throws SignatureValidationException if signature verification fails for some reason
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun verifyUserIdCertification(
            userId: CharSequence,
            signature: PGPSignature,
            primaryKey: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): Boolean {
            return verifyUserIdCertification(
                userId, signature, primaryKey, primaryKey, policy, referenceTime)
        }

        /**
         * Verify a user-id certification.
         *
         * @param userId user-id
         * @param signature certification signature
         * @param signingKey key that created the certification
         * @param keyWithUserId primary key that carries the user-id
         * @param policy policy
         * @param referenceTime reference date for signature verification
         * @return true if signature verification is successful
         * @throws SignatureValidationException if signature verification fails for some reason
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun verifyUserIdCertification(
            userId: CharSequence,
            signature: PGPSignature,
            signingKey: PGPPublicKey,
            keyWithUserId: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): Boolean {
            wasPossiblyMadeByKey(signingKey).verify(signature)
            signatureIsCertification().verify(signature)
            signatureStructureIsAcceptable(signingKey, policy).verify(signature)
            signatureIsEffective(referenceTime).verify(signature)
            correctSignatureOverUserId(userId, keyWithUserId, signingKey).verify(signature)

            return true
        }

        /**
         * Verify a user-id revocation self-signature.
         *
         * @param userId user-id
         * @param signature user-id revocation signature
         * @param primaryKey primary key
         * @param policy policy
         * @param referenceTime reference date for signature verification
         * @return true if the user-id revocation signature is successfully verified
         * @throws SignatureValidationException if signature verification fails for some reason
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun verifyUserIdRevocation(
            userId: CharSequence,
            signature: PGPSignature,
            primaryKey: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): Boolean {
            return verifyUserIdRevocation(
                userId, signature, primaryKey, primaryKey, policy, referenceTime)
        }

        /**
         * Verify a user-id revocation signature.
         *
         * @param userId user-id
         * @param signature revocation signature
         * @param signingKey key that created the revocation signature
         * @param keyWithUserId primary key carrying the user-id
         * @param policy policy
         * @param referenceTime reference date for signature verification
         * @return true if the user-id revocation signature is successfully verified
         * @throws SignatureValidationException if signature verification fails for some reason
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun verifyUserIdRevocation(
            userId: CharSequence,
            signature: PGPSignature,
            signingKey: PGPPublicKey,
            keyWithUserId: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): Boolean {
            wasPossiblyMadeByKey(signingKey).verify(signature)
            signatureIsOfType(SignatureType.CERTIFICATION_REVOCATION).verify(signature)
            signatureStructureIsAcceptable(signingKey, policy).verify(signature)
            signatureIsEffective(referenceTime).verify(signature)
            correctSignatureOverUserId(userId, keyWithUserId, signingKey).verify(signature)

            return true
        }

        /**
         * Verify a certification self-signature over a user-attributes packet.
         *
         * @param userAttributes user attributes
         * @param signature certification self-signature
         * @param primaryKey primary key that carries the user-attributes
         * @param policy policy
         * @param referenceTime reference date for signature verification
         * @return true if the signature can be verified successfully
         * @throws SignatureValidationException if signature verification fails for some reason
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun verifyUserAttributesCertification(
            userAttributes: PGPUserAttributeSubpacketVector,
            signature: PGPSignature,
            primaryKey: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): Boolean {
            return verifyUserAttributesCertification(
                userAttributes, signature, primaryKey, primaryKey, policy, referenceTime)
        }

        /**
         * Verify a certification signature over a user-attributes packet.
         *
         * @param userAttributes user attributes
         * @param signature certification signature
         * @param signingKey key that created the user-attributes certification
         * @param keyWithAttributes key that carries the user-attributes certification
         * @param policy policy
         * @param referenceTime reference date for signature verification
         * @return true if the signature can be verified successfully
         * @throws SignatureValidationException if signature verification fails for some reason
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun verifyUserAttributesCertification(
            userAttributes: PGPUserAttributeSubpacketVector,
            signature: PGPSignature,
            signingKey: PGPPublicKey,
            keyWithAttributes: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): Boolean {
            wasPossiblyMadeByKey(signingKey).verify(signature)
            signatureIsCertification().verify(signature)
            signatureStructureIsAcceptable(signingKey, policy).verify(signature)
            signatureIsEffective(referenceTime).verify(signature)
            correctSignatureOverUserAttributes(userAttributes, keyWithAttributes, signingKey)
                .verify(signature)

            return true
        }

        /**
         * Verify a user-attributes revocation self-signature.
         *
         * @param userAttributes user-attributes
         * @param signature user-attributes revocation signature
         * @param primaryKey primary key that carries the user-attributes
         * @param policy policy
         * @param referenceTime reference date for signature verification
         * @return true if the revocation signature can be verified successfully
         * @throws SignatureValidationException if signature verification fails for some reason
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun verifyUserAttributesRevocation(
            userAttributes: PGPUserAttributeSubpacketVector,
            signature: PGPSignature,
            primaryKey: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): Boolean {
            return verifyUserAttributesRevocation(
                userAttributes, signature, primaryKey, primaryKey, policy, referenceTime)
        }

        /**
         * Verify a user-attributes revocation signature.
         *
         * @param userAttributes user-attributes
         * @param signature revocation signature
         * @param signingKey revocation key
         * @param keyWithAttributes key that carries the user-attributes
         * @param policy policy
         * @param referenceTime reference date for signature verification
         * @return true if the revocation signature can be verified successfully
         * @throws SignatureValidationException if signature verification fails for some reason
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun verifyUserAttributesRevocation(
            userAttributes: PGPUserAttributeSubpacketVector,
            signature: PGPSignature,
            signingKey: PGPPublicKey,
            keyWithAttributes: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): Boolean {
            wasPossiblyMadeByKey(signingKey).verify(signature)
            signatureIsOfType(SignatureType.CERTIFICATION_REVOCATION).verify(signature)
            signatureStructureIsAcceptable(signingKey, policy).verify(signature)
            signatureIsEffective(referenceTime).verify(signature)
            correctSignatureOverUserAttributes(userAttributes, keyWithAttributes, signingKey)
                .verify(signature)

            return true
        }

        /**
         * Verify a subkey binding signature.
         *
         * @param signature binding signature
         * @param primaryKey primary key
         * @param subkey subkey
         * @param policy policy
         * @param referenceTime reference date for signature verification
         * @return true if the binding signature can be verified successfully
         * @throws SignatureValidationException if signature verification fails for some reason
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun verifySubkeyBindingSignature(
            signature: PGPSignature,
            primaryKey: PGPPublicKey,
            subkey: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): Boolean {
            signatureIsOfType(SignatureType.SUBKEY_BINDING).verify(signature)
            signatureStructureIsAcceptable(primaryKey, policy).verify(signature)
            signatureDoesNotPredateSignee(subkey).verify(signature)
            signatureIsEffective(referenceTime).verify(signature)
            hasValidPrimaryKeyBindingSignatureIfRequired(primaryKey, subkey, policy, referenceTime)
                .verify(signature)
            correctSubkeyBindingSignature(primaryKey, subkey).verify(signature)

            return true
        }

        /**
         * Verify a subkey revocation signature.
         *
         * @param signature subkey revocation signature
         * @param primaryKey primary key
         * @param subkey subkey
         * @param policy policy
         * @param referenceTime reference date for signature verification
         * @return true if the subkey revocation signature can be verified successfully
         * @throws SignatureValidationException if signature verification fails for some reason
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun verifySubkeyBindingRevocation(
            signature: PGPSignature,
            primaryKey: PGPPublicKey,
            subkey: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): Boolean {
            signatureIsOfType(SignatureType.SUBKEY_REVOCATION).verify(signature)
            signatureStructureIsAcceptable(primaryKey, policy).verify(signature)
            signatureDoesNotPredateSignee(subkey).verify(signature)
            signatureIsEffective(referenceTime).verify(signature)
            correctSignatureOverKey(primaryKey, subkey).verify(signature)

            return true
        }

        /**
         * Verify a direct-key self-signature.
         *
         * @param signature signature
         * @param primaryKey primary key
         * @param policy policy
         * @param referenceTime reference date for signature verification
         * @return true if the signature can be verified successfully
         * @throws SignatureValidationException if signature verification fails for some reason
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun verifyDirectKeySignature(
            signature: PGPSignature,
            primaryKey: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): Boolean {
            return verifyDirectKeySignature(
                signature, primaryKey, primaryKey, policy, referenceTime)
        }

        /**
         * Verify a direct-key signature.
         *
         * @param signature signature
         * @param signingKey signing key
         * @param signedKey signed key
         * @param policy policy
         * @param referenceTime reference date for signature verification
         * @return true if signature verification is successful
         * @throws SignatureValidationException if signature verification fails for some reason
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun verifyDirectKeySignature(
            signature: PGPSignature,
            signingKey: PGPPublicKey,
            signedKey: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): Boolean {
            signatureIsOfType(SignatureType.DIRECT_KEY).verify(signature)
            signatureStructureIsAcceptable(signingKey, policy).verify(signature)
            signatureDoesNotPredateSignee(signedKey).verify(signature)
            signatureIsEffective(referenceTime).verify(signature)
            correctSignatureOverKey(signingKey, signedKey).verify(signature)

            return true
        }

        /**
         * Verify a key revocation signature.
         *
         * @param signature signature
         * @param primaryKey primary key
         * @param policy policy
         * @param referenceTime reference date for signature verification
         * @return true if signature verification is successful
         * @throws SignatureValidationException if signature verification fails for some reason
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun verifyKeyRevocationSignature(
            signature: PGPSignature,
            primaryKey: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): Boolean {
            signatureIsOfType(SignatureType.KEY_REVOCATION).verify(signature)
            signatureStructureIsAcceptable(primaryKey, policy).verify(signature)
            signatureIsEffective(referenceTime).verify(signature)
            correctSignatureOverKey(primaryKey, primaryKey).verify(signature)

            return true
        }

        /**
         * Initialize a signature and verify it afterwards by updating it with the signed data.
         *
         * @param signature OpenPGP signature
         * @param signedData input stream containing the signed data
         * @param signingKey the key that created the signature
         * @param policy policy
         * @param referenceTime reference date of signature verification
         * @return true if the signature is successfully verified
         * @throws SignatureValidationException if the signature verification fails for some reason
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun verifyUninitializedSignature(
            signature: PGPSignature,
            signedData: InputStream,
            signingKey: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): Boolean {
            initializeSignatureAndUpdateWithSignedData(signature, signedData, signingKey)
            return verifyInitializedSignature(signature, signingKey, policy, referenceTime)
        }

        /**
         * Initialize a signature and then update it with the signed data from the given
         * [InputStream].
         *
         * @param signature OpenPGP signature
         * @param signedData input stream containing signed data
         * @param signingKey key that created the signature
         * @throws SignatureValidationException in case the signature cannot be verified for some
         *   reason
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun initializeSignatureAndUpdateWithSignedData(
            signature: PGPSignature,
            signedData: InputStream,
            signingKey: PGPPublicKey
        ) {
            try {
                signature.init(
                    OpenPGPImplementation.getInstance().pgpContentVerifierBuilderProvider(),
                    signingKey,
                )
                var read: Int
                val buf = ByteArray(8192)
                var lastByte: Byte = -1
                while (signedData.read(buf).also { read = it } != -1) {
                    // If we previously omitted a newline, but the stream is not yet empty, add it
                    // now
                    if (lastByte == '\n'.code.toByte()) {
                        signature.update(lastByte)
                    }
                    lastByte = buf[read - 1]
                    if (lastByte == '\n'.code.toByte()) {
                        // if last byte in buffer is newline, omit it for now
                        signature.update(buf, 0, read - 1)
                    } else {
                        // otherwise, write buffer as usual
                        signature.update(buf, 0, read)
                    }
                }
            } catch (e: PGPException) {
                throw SignatureValidationException("Cannot init signature.", e)
            } catch (e: IOException) {
                throw SignatureValidationException("Cannot update signature.", e)
            }
        }

        /**
         * Verify an initialized signature. An initialized signature was already updated with the
         * signed data.
         *
         * @param signature OpenPGP signature
         * @param signingKey key that created the signature
         * @param policy policy
         * @param referenceTime reference date for signature verification
         * @return true if signature is verified successfully
         * @throws SignatureValidationException if signature verification fails for some reason
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun verifyInitializedSignature(
            signature: PGPSignature,
            signingKey: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): Boolean {
            wasPossiblyMadeByKey(signingKey).verify(signature)
            signatureStructureIsAcceptable(signingKey, policy).verify(signature)
            signatureIsEffective(referenceTime).verify(signature)

            return try {
                if (!signature.verify()) {
                    throw SignatureValidationException("Signature is not correct.")
                }
                true
            } catch (e: PGPException) {
                throw SignatureValidationException("Could not verify signature correctness.", e)
            }
        }

        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun verifyOnePassSignature(
            signature: PGPSignature,
            signingKey: PGPPublicKey,
            onePassSignature: OnePassSignatureCheck,
            policy: Policy
        ): Boolean {
            try {
                wasPossiblyMadeByKey(signingKey).verify(signature)
                signatureStructureIsAcceptable(signingKey, policy).verify(signature)
                signatureIsEffective().verify(signature)
            } catch (e: SignatureValidationException) {
                throw SignatureValidationException("Signature is not valid: ${e.message}", e)
            }

            try {
                checkNotNull(onePassSignature.signature) { "No comparison signature provided." }
                if (!onePassSignature.onePassSignature.verify(signature)) {
                    throw SignatureValidationException(
                        "Bad signature of key ${signingKey.keyID.openPgpKeyId()}")
                }
            } catch (e: PGPException) {
                throw SignatureValidationException(
                    "Could not verify correctness of One-Pass-Signature: ${e.message}", e)
            }

            return true
        }

        /**
         * Verify a signature (certification or revocation) over a user-id.
         *
         * @param userId user-id
         * @param signature self-signature
         * @param primaryKey primary key that created the signature
         * @param policy policy
         * @param referenceTime reference date for signature verification
         * @return true if the signature is successfully verified
         * @throws SignatureValidationException if signature verification fails for some reason
         */
        @JvmStatic
        @Throws(SignatureValidationException::class)
        fun verifySignatureOverUserId(
            userId: CharSequence,
            signature: PGPSignature,
            primaryKey: PGPPublicKey,
            policy: Policy,
            referenceTime: Date
        ): Boolean {
            return verifySignatureOverUserId(
                userId, signature, primaryKey, primaryKey, policy, referenceTime)
        }
    }
}
