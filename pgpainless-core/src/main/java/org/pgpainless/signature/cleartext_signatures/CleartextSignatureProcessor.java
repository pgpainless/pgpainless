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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.util.Strings;
import org.pgpainless.PGPainless;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.signature.CertificateValidator;
import org.pgpainless.util.ArmoredInputStreamFactory;

/**
 * Processor for cleartext-signed messages.
 * Based on Bouncycastle's {@link org.bouncycastle.openpgp.examples.ClearSignedFileProcessor}.
 */
public class CleartextSignatureProcessor {

    private final ArmoredInputStream in;
    private final PGPPublicKeyRingCollection verificationKeys;
    private final MultiPassStrategy multiPassStrategy;

    public CleartextSignatureProcessor(InputStream inputStream,
                                       PGPPublicKeyRingCollection verificationKeys,
                                       MultiPassStrategy multiPassStrategy)
            throws IOException {
        if (inputStream instanceof ArmoredInputStream) {
            this.in = (ArmoredInputStream) inputStream;
        } else {
            this.in = ArmoredInputStreamFactory.get(inputStream);
        }
        this.verificationKeys = verificationKeys;
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
    public PGPSignature process() throws IOException, PGPException {
        if (!in.isClearText()) {
            throw new IllegalStateException("Message is not cleartext.");
        }

        OutputStream out = new BufferedOutputStream(multiPassStrategy.getMessageOutputStream());

        ByteArrayOutputStream lineOut = new ByteArrayOutputStream();
        int lookAhead = readInputLine(lineOut, in);
        byte[] lineSep = getLineSeparator();

        if (lookAhead != -1 && in.isClearText()) {
            byte[] line = lineOut.toByteArray();
            out.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
            out.write(lineSep);

            while (lookAhead != -1 && in.isClearText()) {
                lookAhead = readInputLine(lineOut, lookAhead, in);
                line = lineOut.toByteArray();
                out.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
                out.write(lineSep);
            }
        } else {
            if (lookAhead != -1) {
                byte[] line = lineOut.toByteArray();
                out.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
                out.write(lineSep);
            }
        }

        out.close();

        PGPObjectFactory objectFactory = new PGPObjectFactory(in, ImplementationFactory.getInstance().getKeyFingerprintCalculator());
        PGPSignatureList signatures = (PGPSignatureList) objectFactory.nextObject();
        PGPSignature signature = signatures.get(0);

        PGPPublicKeyRing signingKeyRing = null;
        PGPPublicKey signingKey = null;
        for (PGPPublicKeyRing ring : verificationKeys) {
            signingKey = ring.getPublicKey(signature.getKeyID());
            if (signingKey != null) {
                signingKeyRing = ring;
                break;
            }
        }
        if (signingKey == null) {
            throw new SignatureValidationException("Missing public key " + Long.toHexString(signature.getKeyID()));
        }

        signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), signingKey);

        InputStream sigIn = new BufferedInputStream(multiPassStrategy.getMessageInputStream());
        lookAhead = readInputLine(lineOut, sigIn);
        processLine(signature, lineOut.toByteArray());

        if (lookAhead != -1) {
            do {
                lookAhead = readInputLine(lineOut, lookAhead, sigIn);
                signature.update((byte) '\r');
                signature.update((byte) '\n');
                processLine(signature, lineOut.toByteArray());
            } while (lookAhead != -1);
        }
        sigIn.close();

        CertificateValidator.validateCertificateAndVerifyInitializedSignature(signature, signingKeyRing, PGPainless.getPolicy());
        return signature;
    }

    private static int readInputLine(ByteArrayOutputStream bOut, InputStream fIn)
            throws IOException {
        bOut.reset();

        int lookAhead = -1;
        int ch;

        while ((ch = fIn.read()) >= 0) {
            bOut.write(ch);
            if (ch == '\r' || ch == '\n') {
                lookAhead = readPassedEOL(bOut, ch, fIn);
                break;
            }
        }

        return lookAhead;
    }

    private static int readInputLine(ByteArrayOutputStream bOut, int lookAhead, InputStream fIn)
            throws IOException {
        bOut.reset();

        int ch = lookAhead;

        do {
            bOut.write(ch);
            if (ch == '\r' || ch == '\n') {
                lookAhead = readPassedEOL(bOut, ch, fIn);
                break;
            }
        }
        while ((ch = fIn.read()) >= 0);

        if (ch < 0) {
            lookAhead = -1;
        }

        return lookAhead;
    }

    private static int readPassedEOL(ByteArrayOutputStream bOut, int lastCh, InputStream fIn)
            throws IOException {
        int lookAhead = fIn.read();

        if (lastCh == '\r' && lookAhead == '\n') {
            bOut.write(lookAhead);
            lookAhead = fIn.read();
        }

        return lookAhead;
    }


    private static byte[] getLineSeparator() {
        String nl = Strings.lineSeparator();
        byte[] nlBytes = new byte[nl.length()];

        for (int i = 0; i != nlBytes.length; i++) {
            nlBytes[i] = (byte) nl.charAt(i);
        }

        return nlBytes;
    }

    private static void processLine(PGPSignature sig, byte[] line) {
        int length = getLengthWithoutWhiteSpace(line);
        if (length > 0) {
            sig.update(line, 0, length);
        }
    }

    private static void processLine(OutputStream aOut, PGPSignatureGenerator sGen, byte[] line)
            throws IOException {
        // note: trailing white space needs to be removed from the end of
        // each line for signature calculation RFC 4880 Section 7.1
        int length = getLengthWithoutWhiteSpace(line);
        if (length > 0) {
            sGen.update(line, 0, length);
        }

        aOut.write(line, 0, line.length);
    }

    private static int getLengthWithoutSeparatorOrTrailingWhitespace(byte[] line) {
        int    end = line.length - 1;

        while (end >= 0 && isWhiteSpace(line[end])) {
            end--;
        }

        return end + 1;
    }

    private static boolean isLineEnding(byte b) {
        return b == '\r' || b == '\n';
    }

    private static int getLengthWithoutWhiteSpace(byte[] line) {
        int    end = line.length - 1;

        while (end >= 0 && isWhiteSpace(line[end])) {
            end--;
        }

        return end + 1;
    }

    private static boolean isWhiteSpace(byte b) {
        return isLineEnding(b) || b == '\t' || b == ' ';
    }
}
