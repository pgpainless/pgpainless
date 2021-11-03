// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.pgpainless.signature.consumer.SignatureValidator.signatureWasCreatedInBounds;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.pgpainless.PGPainless;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.consumer.CertificateValidator;
import org.pgpainless.signature.consumer.DetachedSignatureCheck;
import org.pgpainless.signature.consumer.OnePassSignatureCheck;
import org.pgpainless.signature.SignatureUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class SignatureInputStream extends FilterInputStream {

    protected SignatureInputStream(InputStream inputStream) {
        super(inputStream);
    }

    public static class VerifySignatures extends SignatureInputStream {

        private static final Logger LOGGER = LoggerFactory.getLogger(VerifySignatures.class);

        private final PGPObjectFactory objectFactory;
        private final List<OnePassSignatureCheck> opSignatures;
        private final Map<Long, OnePassSignatureCheck> opSignaturesWithMissingCert;
        private final List<DetachedSignatureCheck> detachedSignatures;
        private final ConsumerOptions options;
        private final OpenPgpMetadata.Builder resultBuilder;

        public VerifySignatures(
                InputStream literalDataStream,
                PGPObjectFactory objectFactory,
                List<OnePassSignatureCheck> opSignatures,
                Map<Long, OnePassSignatureCheck> onePassSignaturesWithMissingCert,
                List<DetachedSignatureCheck> detachedSignatures,
                ConsumerOptions options,
                OpenPgpMetadata.Builder resultBuilder) {
            super(literalDataStream);
            this.objectFactory = objectFactory;
            this.opSignatures = opSignatures;
            this.opSignaturesWithMissingCert = onePassSignaturesWithMissingCert;
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
                parseAndCombineSignatures();
                verifyOnePassSignatures();
                verifyDetachedSignatures();
            } else {
                updateOnePassSignatures(b, off, read);
                updateDetachedSignatures(b, off, read);
            }
            return read;
        }

        public void parseAndCombineSignatures() throws IOException {
            // Parse signatures from message
            PGPSignatureList signatures;
            try {
                signatures = parseSignatures(objectFactory);
            } catch (IOException e) {
                return;
            }
            List<PGPSignature> signatureList = SignatureUtils.toList(signatures);
            // Set signatures as comparison sigs in OPS checks
            for (int i = 0; i < opSignatures.size(); i++) {
                int reversedIndex = opSignatures.size() - i - 1;
                opSignatures.get(i).setSignature(signatureList.get(reversedIndex));
            }

            for (PGPSignature signature : signatureList) {
                if (opSignaturesWithMissingCert.containsKey(signature.getKeyID())) {
                    OnePassSignatureCheck check = opSignaturesWithMissingCert.remove(signature.getKeyID());
                    check.setSignature(signature);

                    resultBuilder.addInvalidInbandSignature(new SignatureVerification(signature, null),
                            new SignatureValidationException("Missing verification certificate " + Long.toHexString(signature.getKeyID())));
                }
            }
        }

        private PGPSignatureList parseSignatures(PGPObjectFactory objectFactory) throws IOException {
            PGPSignatureList signatureList = null;
            Object pgpObject = objectFactory.nextObject();
            while (pgpObject !=  null && signatureList == null) {
                if (pgpObject instanceof PGPSignatureList) {
                    signatureList = (PGPSignatureList) pgpObject;
                } else {
                    pgpObject = objectFactory.nextObject();
                }
            }

            if (signatureList == null || signatureList.isEmpty()) {
                throw new IOException("Verification failed - No Signatures found");
            }

            return signatureList;
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
            for (DetachedSignatureCheck s : detachedSignatures) {
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
            for (DetachedSignatureCheck detachedSignature : detachedSignatures) {
                detachedSignature.getSignature().update(b);
            }
        }

        private void updateDetachedSignatures(byte[] b, int off, int read) {
            for (DetachedSignatureCheck detachedSignature : detachedSignatures) {
                detachedSignature.getSignature().update(b, off, read);
            }
        }

    }
}
