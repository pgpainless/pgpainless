// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.decryption_verification.SignatureVerification
import sop.Verification
import sop.enums.SignatureMode

/** Helper class for shared methods related to [Verification] objects. */
class VerificationHelper {

    companion object {

        /**
         * Map a [SignatureVerification] object to a [Verification].
         *
         * @param sigVerification signature verification
         * @return verification
         */
        @JvmStatic
        fun mapVerification(sigVerification: SignatureVerification): Verification =
            Verification(
                sigVerification.signature.creationTime,
                sigVerification.signingKey.subkeyFingerprint.toString(),
                sigVerification.signingKey.primaryKeyFingerprint.toString(),
                getMode(sigVerification.signature),
                null)

        /**
         * Map an OpenPGP signature type to a [SignatureMode] enum. Note: This method only maps
         * [PGPSignature.BINARY_DOCUMENT] and [PGPSignature.CANONICAL_TEXT_DOCUMENT]. Other values
         * are mapped to `null`.
         *
         * @param signature signature
         * @return signature mode enum or null
         */
        @JvmStatic
        fun getMode(signature: PGPSignature): SignatureMode? =
            when (signature.signatureType) {
                PGPSignature.BINARY_DOCUMENT -> SignatureMode.binary
                PGPSignature.CANONICAL_TEXT_DOCUMENT -> SignatureMode.text
                else -> null
            }
    }
}
