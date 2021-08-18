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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.util.Strings;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.util.ArmoredInputStreamFactory;

/**
 * Utility class to deal with cleartext-signed messages.
 * Based on Bouncycastle's {@link org.bouncycastle.openpgp.examples.ClearSignedFileProcessor}.
 */
public final class ClearsignedMessageUtil {

    private ClearsignedMessageUtil() {

    }

    /**
     * Dearmor a clearsigned message, detach the inband signatures and write the plaintext message to the provided
     * messageOutputStream.
     *
     * @param clearsignedInputStream input stream containing a clearsigned message
     * @param messageOutputStream output stream to which the dearmored message shall be written
     * @return signatures
     * @throws IOException if the message is not clearsigned or some other IO error happens
     */
    public static PGPSignatureList detachSignaturesFromInbandClearsignedMessage(InputStream clearsignedInputStream,
                                                                                OutputStream messageOutputStream)
            throws IOException {
        ArmoredInputStream in = ArmoredInputStreamFactory.get(clearsignedInputStream);
        if (!in.isClearText()) {
            throw new IOException("Message is not clearsigned.");
        }

        OutputStream out = new BufferedOutputStream(messageOutputStream);
        try {
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
        } finally {
            out.close();
        }

        PGPObjectFactory objectFactory = new PGPObjectFactory(in, ImplementationFactory.getInstance().getKeyFingerprintCalculator());
        PGPSignatureList signatures = (PGPSignatureList) objectFactory.nextObject();

        return signatures;
    }

    /**
     * Initialize the given signature by processing the data from the messageData input stream.
     *
     * @param signature uninitialized signature
     * @param signingKey public signing key
     * @param messageData input stream containing the data to which the signature belongs
     * @return initialized signature
     *
     * @throws PGPException if the signature cannot be initialized
     * @throws IOException if an IO error happens
     */
    public static PGPSignature initializeSignature(PGPSignature signature, PGPPublicKey signingKey, InputStream messageData)
            throws PGPException, IOException {
        signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), signingKey);

        InputStream sigIn = new BufferedInputStream(messageData);
        ByteArrayOutputStream lineOut = new ByteArrayOutputStream();
        int lookAhead = readInputLine(lineOut, sigIn);
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
        return signature;
    }

    public static int readInputLine(ByteArrayOutputStream bOut, InputStream fIn)
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

    public static int readInputLine(ByteArrayOutputStream bOut, int lookAhead, InputStream fIn)
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

    public static void processLine(PGPSignature sig, byte[] line) {
        int length = getLengthWithoutWhiteSpace(line);
        if (length > 0) {
            sig.update(line, 0, length);
        }
    }

    public static void processLine(OutputStream aOut, PGPSignatureGenerator sGen, byte[] line)
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
