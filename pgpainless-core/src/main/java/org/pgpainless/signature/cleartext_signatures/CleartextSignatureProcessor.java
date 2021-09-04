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
package org.pgpainless.signature.cleartext_signatures;

import static org.pgpainless.signature.SignatureValidator.signatureWasCreatedInBounds;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.signature.CertificateValidator;
import org.pgpainless.signature.SignatureVerifier;
import org.pgpainless.util.ArmoredInputStreamFactory;

/**
 * Processor for cleartext-signed messages.
 */
public class CleartextSignatureProcessor {

    private static final Logger LOGGER = Logger.getLogger(CleartextSignatureProcessor.class.getName());

    private final ArmoredInputStream in;
    private final ConsumerOptions options;
    private final MultiPassStrategy multiPassStrategy;

    public CleartextSignatureProcessor(InputStream inputStream,
                                       ConsumerOptions options,
                                       MultiPassStrategy multiPassStrategy)
            throws IOException {
        if (inputStream instanceof ArmoredInputStream) {
            this.in = (ArmoredInputStream) inputStream;
        } else {
            this.in = ArmoredInputStreamFactory.get(inputStream);
        }
        this.options = options;
        this.multiPassStrategy = multiPassStrategy;
    }

    /**
     * Unpack the message from the ascii armor and process the signature.
     * This method only returns the signature, if it is correct.
     *
     * After the message has been processed, the content can be retrieved from the {@link MultiPassStrategy}.
     * If an {@link InMemoryMultiPassStrategy} was used, the message can be accessed via {@link InMemoryMultiPassStrategy#getBytes()}.
     * If {@link MultiPassStrategy#writeMessageToFile(File)} was used, the message content was written to the given file.
     *
     * @return validated signature
     * @throws IOException if the signature cannot be read.
     * @throws PGPException if the signature cannot be initialized.
     * @throws SignatureValidationException if the signature is invalid.
     */
    public OpenPgpMetadata process() throws IOException, PGPException {
        OpenPgpMetadata.Builder resultBuilder = OpenPgpMetadata.getBuilder();
        resultBuilder.setCompressionAlgorithm(CompressionAlgorithm.UNCOMPRESSED)
                .setSymmetricKeyAlgorithm(SymmetricKeyAlgorithm.NULL)
                .setFileEncoding(StreamEncoding.TEXT);

        PGPSignatureList signatures = ClearsignedMessageUtil.detachSignaturesFromInbandClearsignedMessage(in, multiPassStrategy.getMessageOutputStream());

        for (PGPSignature signature : signatures) {
            PGPPublicKeyRing certificate = null;
            PGPPublicKey signingKey = null;
            for (PGPPublicKeyRing cert : options.getCertificates()) {
                signingKey = cert.getPublicKey(signature.getKeyID());
                if (signingKey != null) {
                    certificate = cert;
                    break;
                }
            }

            try {
                if (signingKey == null) {
                    throw new SignatureValidationException("Missing verification key with key-id " + Long.toHexString(signature.getKeyID()));
                }

                SubkeyIdentifier signingKeyIdentifier = new SubkeyIdentifier(certificate, signingKey.getKeyID());

                signatureWasCreatedInBounds(options.getVerifyNotBefore(), options.getVerifyNotAfter()).verify(signature);
                SignatureVerifier.initializeSignatureAndUpdateWithSignedData(signature, multiPassStrategy.getMessageInputStream(), signingKey);
                CertificateValidator.validateCertificateAndVerifyInitializedSignature(signature, certificate, PGPainless.getPolicy());
                resultBuilder.addVerifiedInbandSignature(new SignatureVerification(signature, signingKeyIdentifier));
            } catch (SignatureValidationException e) {
                LOGGER.log(Level.INFO, "Cannot verify signature made by key " + Long.toHexString(signature.getKeyID()) + ": " + e.getMessage());
                SubkeyIdentifier signingKeyIdentifier = null;
                if (signingKey != null) {
                    signingKeyIdentifier = new SubkeyIdentifier(certificate, signingKey.getKeyID());
                }
                resultBuilder.addInvalidInbandSignature(new SignatureVerification(signature, signingKeyIdentifier), e);
            }
        }

        return resultBuilder.build();
    }

}
