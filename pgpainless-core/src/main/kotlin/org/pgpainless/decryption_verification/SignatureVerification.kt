// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification

import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.decryption_verification.SignatureVerification.Failure
import org.pgpainless.exception.SignatureValidationException
import org.pgpainless.key.SubkeyIdentifier
import org.pgpainless.signature.SignatureUtils

/**
 * Tuple of a signature and an identifier of its corresponding verification key.
 * Semantic meaning of the signature verification (success, failure) is merely given by context.
 * E.g. [MessageMetadata.getVerifiedInlineSignatures] contains verified verifications,
 * while the class [Failure] contains failed verifications.
 *
 * @param signature PGPSignature object
 * @param signingKey [SubkeyIdentifier] of the (sub-) key that is used for signature verification.
 * Note, that this might be null, e.g. in case of a [Failure] due to missing verification key.
 */
data class SignatureVerification(
        val signature: PGPSignature,
        val signingKey: SubkeyIdentifier
) {

    override fun toString(): String {
        return "Signature: ${SignatureUtils.getSignatureDigestPrefix(signature)};" +
                " Key: $signingKey;"
    }

    /**
     * Tuple object of a [SignatureVerification] and the corresponding [SignatureValidationException]
     * that caused the verification to fail.
     *
     * @param signatureVerification verification (tuple of [PGPSignature] and corresponding [SubkeyIdentifier])
     * @param validationException exception that caused the verification to fail
     */
    data class Failure(
            val signature: PGPSignature,
            val signingKey: SubkeyIdentifier?,
            val validationException: SignatureValidationException
    ) {

        constructor(verification: SignatureVerification, validationException: SignatureValidationException):
                this(verification.signature, verification.signingKey, validationException)

        override fun toString(): String {
            return "Signature: ${SignatureUtils.getSignatureDigestPrefix(signature)}; Key: ${signingKey?.toString() ?: "null"}; Failure: ${validationException.message}"
        }
    }
}