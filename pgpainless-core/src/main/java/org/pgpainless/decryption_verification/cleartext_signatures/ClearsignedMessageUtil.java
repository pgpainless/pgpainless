// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.cleartext_signatures;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.util.Strings;
import org.pgpainless.exception.WrongConsumingMethodException;
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
            throws IOException, WrongConsumingMethodException {
        ArmoredInputStream in = ArmoredInputStreamFactory.get(clearsignedInputStream);
        if (!in.isClearText()) {
            throw new WrongConsumingMethodException("Message is not using the Cleartext Signature Framework.");
        }

        OutputStream out = new BufferedOutputStream(messageOutputStream);
        try {
            ByteArrayOutputStream lineOut = new ByteArrayOutputStream();
            int lookAhead = readInputLine(lineOut, in);
            byte[] lineSep = getLineSeparator();

            if (lookAhead != -1 && in.isClearText()) {
                byte[] line = lineOut.toByteArray();
                out.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));

                while (lookAhead != -1 && in.isClearText()) {
                    lookAhead = readInputLine(lineOut, lookAhead, in);
                    line = lineOut.toByteArray();
                    out.write(lineSep);
                    out.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
                }
            } else {
                if (lookAhead != -1) {
                    byte[] line = lineOut.toByteArray();
                    out.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
                }
            }
        } finally {
            out.close();
        }

        PGPObjectFactory objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(in);
        PGPSignatureList signatures = (PGPSignatureList) objectFactory.nextObject();

        return signatures;
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

    private static boolean isWhiteSpace(byte b) {
        return isLineEnding(b) || b == '\t' || b == ' ';
    }
}
