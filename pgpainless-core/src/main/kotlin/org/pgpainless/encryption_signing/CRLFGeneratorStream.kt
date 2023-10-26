// SPDX-FileCopyrightText: 2021 David Hook <dgh@cryptoworkshop.com>
// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing

import java.io.OutputStream
import org.pgpainless.algorithm.StreamEncoding

/**
 * [OutputStream] which applies CR-LF encoding of its input data, based on the desired
 * [StreamEncoding]. This implementation originates from the Bouncy Castle library.
 */
class CRLFGeneratorStream(private val crlfOut: OutputStream, encoding: StreamEncoding) :
    OutputStream() {

    private val isBinary: Boolean
    private var lastB = 0

    init {
        isBinary = encoding == StreamEncoding.BINARY
    }

    override fun write(b: Int) {
        if (!isBinary) {
            if (b == '\n'.code && lastB != '\r'.code) { // Unix
                crlfOut.write('\r'.code)
            } else if (lastB == '\r'.code) { // MAC
                if (b != '\n'.code) {
                    crlfOut.write('\n'.code)
                }
            }
            lastB = b
        }
        crlfOut.write(b)
    }

    override fun close() {
        if (!isBinary && lastB == 'r'.code) {
            crlfOut.write('\n'.code)
        }
        crlfOut.close()
    }

    override fun flush() {
        super.flush()
        crlfOut.flush()
    }
}
