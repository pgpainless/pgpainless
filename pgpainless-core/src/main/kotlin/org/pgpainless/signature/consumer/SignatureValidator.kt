// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature.consumer

import java.util.Date
import openpgp.formatUTC
import openpgp.openPgpKeyId
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.bouncycastle.extensions.fingerprint
import org.pgpainless.exception.SignatureValidationException
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.signature.subpackets.SignatureSubpacketsUtil

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
