// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification

import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.api.OpenPGPSignature.OpenPGPDocumentSignature
import org.pgpainless.decryption_verification.SignatureVerification.Failure
import org.pgpainless.exception.SignatureValidationException
import org.pgpainless.key.SubkeyIdentifier
import org.pgpainless.signature.SignatureUtils

/**
 * Tuple of a signature and an identifier of its corresponding verification key. Semantic meaning of
 * the signature verification (success, failure) is merely given by context. E.g.
 * [MessageMetadata.verifiedSignatures] contains verified verifications, while the class [Failure]
 * contains failed verifications.
 *
 * @param documentSignature OpenPGPDocumentSignature object
 */
data class SignatureVerification(val documentSignature: OpenPGPDocumentSignature) {

    /** Underlying [PGPSignature]. */
    val signature: PGPSignature = documentSignature.signature

    /** [SubkeyIdentifier] of the component key that created the signature. */
    val signingKey: SubkeyIdentifier = SubkeyIdentifier(documentSignature.issuer)

    override fun toString(): String {
        return "Signature: ${SignatureUtils.getSignatureDigestPrefix(signature)};" +
            " Key: $signingKey;"
    }

    /**
     * Tuple object of a [SignatureVerification] and the corresponding
     * [SignatureValidationException] that caused the verification to fail.
     *
     * @param documentSignature signature that could not be verified
     * @param validationException exception that caused the verification to fail
     */
    data class Failure(
        val documentSignature: OpenPGPDocumentSignature,
        val validationException: SignatureValidationException
    ) {

        /** Underlying [PGPSignature]. */
        val signature: PGPSignature = documentSignature.signature

        /**
         * [SubkeyIdentifier] of the component key that created the signature. Note: In case of a
         * missing verification key, this might be null.
         */
        val signingKey: SubkeyIdentifier? = documentSignature.issuer?.let { SubkeyIdentifier(it) }

        constructor(
            verification: SignatureVerification,
            validationException: SignatureValidationException
        ) : this(verification.documentSignature, validationException)

        override fun toString(): String {
            return "Signature: ${SignatureUtils.getSignatureDigestPrefix(signature)}; Key: ${signingKey?.toString() ?: "null"}; Failure: ${validationException.message}"
        }
    }
}
