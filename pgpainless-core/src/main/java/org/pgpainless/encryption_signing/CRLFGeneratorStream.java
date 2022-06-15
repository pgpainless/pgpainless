// SPDX-FileCopyrightText: 2021 David Hook <dgh@cryptoworkshop.com>
// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import org.pgpainless.algorithm.StreamEncoding;

import java.io.IOException;
import java.io.OutputStream;

/**
 * {@link OutputStream} which applies CR-LF encoding of its input data, based on the desired {@link StreamEncoding}.
 * This implementation originates from the Bouncy Castle library.
 */
public class CRLFGeneratorStream extends OutputStream {

    protected final OutputStream crlfOut;
    private final boolean isBinary;
    private int lastB = 0;

    public CRLFGeneratorStream(OutputStream crlfOut, StreamEncoding encoding) {
        this.crlfOut = crlfOut;
        this.isBinary = encoding == StreamEncoding.BINARY;
    }

    public void write(int b) throws IOException {
        if (!isBinary) {
            if (b == '\n' && lastB != '\r') {   // Unix
                crlfOut.write('\r');
            } else if (lastB == '\r') {         // MAC
                if (b != '\n') {
                    crlfOut.write('\n');
                }
            }
            lastB = b;
        }

        crlfOut.write(b);
    }

    public void close() throws IOException {
        if (!isBinary && lastB == '\r') {       // MAC
            crlfOut.write('\n');
        }
        crlfOut.close();
    }

    @Override
    public void flush() throws IOException {
        super.flush();
        crlfOut.flush();
    }
}
