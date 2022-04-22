// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;

import org.bouncycastle.openpgp.PGPObjectFactory;
import org.pgpainless.implementation.ImplementationFactory;

public class OpenPgpInputStream extends BufferedInputStream {

    private static final byte[] ARMOR_HEADER = "-----BEGIN PGP ".getBytes(Charset.forName("UTF8"));

    // Buffer beginning bytes of the data
    public static final int MAX_BUFFER_SIZE = 8192 * 2;

    private final byte[] buffer;
    private final int bufferLen;

    private boolean containsArmorHeader;
    private boolean containsOpenPgpPackets;

    public OpenPgpInputStream(InputStream in) throws IOException {
        super(in, MAX_BUFFER_SIZE);

        mark(MAX_BUFFER_SIZE);
        buffer = new byte[MAX_BUFFER_SIZE];
        bufferLen = read(buffer);
        reset();

        inspectBuffer();
    }

    private void inspectBuffer() {
        if (determineIsArmored()) {
            return;
        }

        determineIsBinaryOpenPgp();
    }

    private boolean determineIsArmored() {
        if (startsWithIgnoringWhitespace(buffer, ARMOR_HEADER, bufferLen)) {
            containsArmorHeader = true;
            return true;
        }
        return false;
    }

    /**
     * This method is still brittle.
     * Basically we try to parse OpenPGP packets from the buffer.
     * If we run into exceptions, then we know that the data is non-OpenPGP'ish.
     *
     * This breaks down though if we read plausible garbage where the data accidentally makes sense,
     * or valid, yet incomplete packets (remember, we are still only working on a portion of the data).
     */
    private void determineIsBinaryOpenPgp() {
        if (bufferLen == -1) {
            // Empty data
            return;
        }

        try {
            ByteArrayInputStream bufferIn = new ByteArrayInputStream(buffer, 0, bufferLen);
            PGPObjectFactory objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(bufferIn);

            boolean containsPackets = false;
            while (objectFactory.nextObject() != null) {
                containsPackets = true;
                // read all packets in buffer - hope to confirm invalid data via thrown IOExceptions
            }
            containsOpenPgpPackets = containsPackets;

        } catch (IOException e) {
            String msg = e.getMessage();

            // If true, we *probably* hit valid, but large OpenPGP data (not sure though) :/
            // Otherwise we hit garbage and can be sure that this is no OpenPGP data \o/
            containsOpenPgpPackets = (msg != null && msg.contains("premature end of stream in PartialInputStream"));

            // This is not an optimal way of determining the nature of data, but probably the best
            // we can do :/
        }
    }

    private boolean startsWithIgnoringWhitespace(byte[] bytes, byte[] subsequence, int bufferLen) {
        if (bufferLen == -1) {
            return false;
        }

        for (int i = 0; i < bufferLen; i++) {
            // Working on bytes is not trivial with unicode data, but its good enough here
            if (Character.isWhitespace(bytes[i])) {
                continue;
            }

            if ((i + subsequence.length) > bytes.length) {
                return false;
            }

            for (int j = 0; j < subsequence.length; j++) {
                if (bytes[i + j] != subsequence[j]) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    public boolean isAsciiArmored() {
        return containsArmorHeader;
    }

    public boolean isBinaryOpenPgp() {
        return containsOpenPgpPackets;
    }

    public boolean isNonOpenPgp() {
        return !isAsciiArmored() && !isBinaryOpenPgp();
    }
}
