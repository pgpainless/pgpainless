// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.decryption_verification.SignatureVerification;
import sop.Verification;
import sop.enums.SignatureMode;

/**
 * Helper class for shared methods related to {@link Verification Verifications}.
 */
public class VerificationHelper {

    /**
     * Map a {@link SignatureVerification} object to a {@link Verification}.
     *
     * @param sigVerification signature verification
     * @return verification
     */
    public static Verification mapVerification(SignatureVerification sigVerification) {
        return new Verification(
                sigVerification.getSignature().getCreationTime(),
                sigVerification.getSigningKey().getSubkeyFingerprint().toString(),
                sigVerification.getSigningKey().getPrimaryKeyFingerprint().toString(),
                getMode(sigVerification.getSignature()),
                null);
    }

    /**
     * Map an OpenPGP signature type to a {@link SignatureMode} enum.
     * Note: This method only maps {@link PGPSignature#BINARY_DOCUMENT} and {@link PGPSignature#CANONICAL_TEXT_DOCUMENT}.
     * Other values are mapped to <pre>null</pre>.
     *
     * @param signature signature
     * @return signature mode enum or null
     */
    private static SignatureMode getMode(PGPSignature signature) {

        if (signature.getSignatureType() == PGPSignature.BINARY_DOCUMENT) {
            return SignatureMode.binary;
        }

        if (signature.getSignatureType() == PGPSignature.CANONICAL_TEXT_DOCUMENT) {
            return SignatureMode.text;
        }

        return null;
    }
}
