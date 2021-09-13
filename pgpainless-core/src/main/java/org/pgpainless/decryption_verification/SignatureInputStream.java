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

import static org.pgpainless.signature.SignatureValidator.signatureWasCreatedInBounds;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.PGPainless;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.CertificateValidator;
import org.pgpainless.signature.DetachedSignature;
import org.pgpainless.signature.OnePassSignatureCheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class SignatureInputStream extends FilterInputStream {

    protected SignatureInputStream(InputStream inputStream) {
        super(inputStream);
    }

    public static class VerifySignatures extends SignatureInputStream {

        private static final Logger LOGGER = LoggerFactory.getLogger(VerifySignatures.class);

        private final List<OnePassSignatureCheck> opSignatures;
        private final List<DetachedSignature> detachedSignatures;
        private final ConsumerOptions options;
        private final OpenPgpMetadata.Builder resultBuilder;

        public VerifySignatures(
                InputStream literalDataStream,
                List<OnePassSignatureCheck> opSignatures,
                List<DetachedSignature> detachedSignatures,
                ConsumerOptions options,
                OpenPgpMetadata.Builder resultBuilder) {
            super(literalDataStream);
            this.opSignatures = opSignatures;
            this.detachedSignatures = detachedSignatures;
            this.options = options;
            this.resultBuilder = resultBuilder;
        }

        @Override
        public int read() throws IOException {
            final int data = super.read();
            final boolean endOfStream = data == -1;
            if (endOfStream) {
                verifyOnePassSignatures();
                verifyDetachedSignatures();
            } else {
                byte b = (byte) data;
                updateOnePassSignatures(b);
                updateDetachedSignatures(b);
            }
            return data;
        }

        @Override
        public int read(@Nonnull byte[] b, int off, int len) throws IOException {
            int read = super.read(b, off, len);

            final boolean endOfStream = read == -1;
            if (endOfStream) {
                verifyOnePassSignatures();
                verifyDetachedSignatures();
            } else {
                updateOnePassSignatures(b, off, read);
                updateDetachedSignatures(b, off, read);
            }
            return read;
        }

        private synchronized void verifyOnePassSignatures() {
            Policy policy = PGPainless.getPolicy();
            for (OnePassSignatureCheck opSignature : opSignatures) {
                if (opSignature.getSignature() == null) {
                    LOGGER.warn("Found OnePassSignature without respective signature packet -> skip");
                    continue;
                }

                try {
                    signatureWasCreatedInBounds(options.getVerifyNotBefore(), options.getVerifyNotAfter()).verify(opSignature.getSignature());
                    CertificateValidator.validateCertificateAndVerifyOnePassSignature(opSignature, policy);
                    resultBuilder.addVerifiedInbandSignature(new SignatureVerification(opSignature.getSignature(), opSignature.getSigningKey()));
                } catch (SignatureValidationException e) {
                    LOGGER.warn("One-pass-signature verification failed for signature made by key {}: {}",
                            opSignature.getSigningKey(), e.getMessage(), e);
                    resultBuilder.addInvalidInbandSignature(new SignatureVerification(opSignature.getSignature(), opSignature.getSigningKey()), e);
                }
            }
        }

        private void verifyDetachedSignatures() {
            Policy policy = PGPainless.getPolicy();
            for (DetachedSignature s : detachedSignatures) {
                try {
                    signatureWasCreatedInBounds(options.getVerifyNotBefore(), options.getVerifyNotAfter()).verify(s.getSignature());
                    CertificateValidator.validateCertificateAndVerifyInitializedSignature(s.getSignature(), (PGPPublicKeyRing) s.getSigningKeyRing(), policy);
                    resultBuilder.addVerifiedDetachedSignature(new SignatureVerification(s.getSignature(), s.getSigningKeyIdentifier()));
                } catch (SignatureValidationException e) {
                    LOGGER.warn("One-pass-signature verification failed for signature made by key {}: {}",
                            s.getSigningKeyIdentifier(), e.getMessage(), e);
                    resultBuilder.addInvalidDetachedSignature(new SignatureVerification(s.getSignature(), s.getSigningKeyIdentifier()), e);
                }
            }
        }

        private void updateOnePassSignatures(byte data) {
            for (OnePassSignatureCheck opSignature : opSignatures) {
                opSignature.getOnePassSignature().update(data);
            }
        }

        private void updateOnePassSignatures(byte[] bytes, int offset, int length) {
            for (OnePassSignatureCheck opSignature : opSignatures) {
                opSignature.getOnePassSignature().update(bytes, offset, length);
            }
        }

        private void updateDetachedSignatures(byte b) {
            for (DetachedSignature detachedSignature : detachedSignatures) {
                detachedSignature.getSignature().update(b);
            }
        }

        private void updateDetachedSignatures(byte[] b, int off, int read) {
            for (DetachedSignature detachedSignature : detachedSignatures) {
                detachedSignature.getSignature().update(b, off, read);
            }
        }

    }

    public static class CleartextSignatures extends SignatureInputStream {
        public CleartextSignatures(InputStream inputStream, List<PGPSignature> signatures) {
            super(inputStream);
        }
    }
}
