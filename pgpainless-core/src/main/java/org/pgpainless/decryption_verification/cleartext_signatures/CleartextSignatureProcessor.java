// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.cleartext_signatures;

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Logger;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.exception.SignatureValidationException;
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
     * Perform the first pass of cleartext signed message processing:
     * Unpack the message from the ascii armor and detach signatures.
     * The plaintext message is being written to cache/disk according to the used {@link MultiPassStrategy}.
     *
     * The result of this method is a {@link DecryptionStream} which will perform the second pass.
     * It again outputs the plaintext message and performs signature verification.
     *
     * The result of {@link DecryptionStream#getResult()} contains information about the messages signatures.
     *
     * @return validated signature
     * @throws IOException if the signature cannot be read.
     * @throws PGPException if the signature cannot be initialized.
     * @throws SignatureValidationException if the signature is invalid.
     */
    public DecryptionStream getVerificationStream() throws IOException, PGPException {
        OpenPgpMetadata.Builder resultBuilder = OpenPgpMetadata.getBuilder();
        resultBuilder.setCompressionAlgorithm(CompressionAlgorithm.UNCOMPRESSED)
                .setSymmetricKeyAlgorithm(SymmetricKeyAlgorithm.NULL)
                .setFileEncoding(StreamEncoding.TEXT);

        PGPSignatureList signatures = ClearsignedMessageUtil.detachSignaturesFromInbandClearsignedMessage(in, multiPassStrategy.getMessageOutputStream());

        for (PGPSignature signature : signatures) {
            options.addVerificationOfDetachedSignature(signature);
        }

        return PGPainless.decryptAndOrVerify()
                .onInputStream(multiPassStrategy.getMessageInputStream())
                .withOptions(options);
    }

}
