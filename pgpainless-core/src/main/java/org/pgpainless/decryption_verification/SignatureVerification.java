/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.decryption_verification;

import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.key.SubkeyIdentifier;

/**
 * Tuple of a signature and an identifier of its corresponding verification key.
 * Semantic meaning of the signature verification (success, failure) is merely given by context.
 * E.g. {@link OpenPgpMetadata#getVerifiedInbandSignatures()} contains verified verifications,
 * while the class {@link Failure} contains failed verifications.
 */
public class SignatureVerification {

    private final PGPSignature signature;
    private final SubkeyIdentifier signingKey;

    /**
     * Construct a verification tuple.
     *
     * @param signature PGPSignature object
     * @param signingKey identifier of the signing key
     */
    public SignatureVerification(PGPSignature signature, @Nullable SubkeyIdentifier signingKey) {
        this.signature = signature;
        this.signingKey = signingKey;
    }

    /**
     * Return the {@link PGPSignature}.
     *
     * @return signature
     */
    public PGPSignature getSignature() {
        return signature;
    }

    /**
     * Return a {@link SubkeyIdentifier} of the (sub-) key that is used for signature verification.
     * Note, that this method might return null, e.g. in case of a {@link Failure} due to missing verification key.
     *
     * @return verification key identifier
     */
    @Nullable
    public SubkeyIdentifier getSigningKey() {
        return signingKey;
    }

    /**
     * Tuple object of a {@link SignatureVerification} and the corresponding {@link SignatureValidationException}
     * that caused the verification to fail.
     */
    public static class Failure {

        private final SignatureVerification signatureVerification;
        private final SignatureValidationException validationException;

        /**
         * Construct a signature verification failure object.
         *
         * @param verification verification
         * @param validationException exception that caused the verification to fail
         */
        public Failure(SignatureVerification verification, SignatureValidationException validationException) {
            this.signatureVerification = verification;
            this.validationException = validationException;
        }

        /**
         * Return the verification (tuple of {@link PGPSignature} and corresponding {@link SubkeyIdentifier}
         * of the signing/verification key.
         *
         * @return verification
         */
        public SignatureVerification getSignatureVerification() {
            return signatureVerification;
        }

        /**
         * Return the {@link SignatureValidationException} that caused the verification to fail.
         *
         * @return exception
         */
        public SignatureValidationException getValidationException() {
            return validationException;
        }
    }
}
