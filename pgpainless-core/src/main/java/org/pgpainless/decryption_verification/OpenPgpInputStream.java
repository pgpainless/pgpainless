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
    public static final int MAX_BUFFER_SIZE = 8192;

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

    private void determineIsBinaryOpenPgp() {
        if (bufferLen == -1) {
            // Empty data
            return;
        }

        try {
            ByteArrayInputStream bufferIn = new ByteArrayInputStream(buffer, 0, bufferLen);
            PGPObjectFactory objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(bufferIn);
            while (objectFactory.nextObject() != null) {
                // read all packets in buffer
            }
            containsOpenPgpPackets = true;
        } catch (IOException e) {
            if (e.getMessage().contains("premature end of stream in PartialInputStream")) {
                // We *probably* hit valid, but large OpenPGP data
                // This is not an optimal way of determining the nature of data, but probably the best
                // we can get from BC.
                containsOpenPgpPackets = true;
            }
            // else: seemingly random, non-OpenPGP data
        }
    }

    private boolean startsWith(byte[] bytes, byte[] subsequence, int bufferLen) {
        return indexOfSubsequence(bytes, subsequence, bufferLen) == 0;
    }

    private int indexOfSubsequence(byte[] bytes, byte[] subsequence, int bufferLen) {
        if (bufferLen == -1) {
            return -1;
        }
        // Naive implementation
        // TODO: Could be improved by using e.g. Knuth-Morris-Pratt algorithm.
        for (int i = 0; i < bufferLen; i++) {
            if ((i + subsequence.length) <= bytes.length) {
                boolean found = true;
                for (int j = 0; j < subsequence.length; j++) {
                    if (bytes[i + j] != subsequence[j]) {
                        found = false;
                        break;
                    }
                }

                if (found) {
                    return i;
                }
            }
        }
        return -1;
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
