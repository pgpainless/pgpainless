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

public class SignatureVerification {

    private final PGPSignature signature;
    private final SubkeyIdentifier signingKey;

    public SignatureVerification(PGPSignature signature, @Nullable SubkeyIdentifier signingKey) {
        this.signature = signature;
        this.signingKey = signingKey;
    }

    public PGPSignature getSignature() {
        return signature;
    }

    @Nullable
    public SubkeyIdentifier getSigningKey() {
        return signingKey;
    }

    public static class Failure {
        private final SignatureVerification signatureVerification;
        private final SignatureValidationException validationException;

        public Failure(SignatureVerification verification, SignatureValidationException validationException) {
            this.signatureVerification = verification;
            this.validationException = validationException;
        }

        public SignatureVerification getSignatureVerification() {
            return signatureVerification;
        }

        public SignatureValidationException getValidationException() {
            return validationException;
        }
    }
}
