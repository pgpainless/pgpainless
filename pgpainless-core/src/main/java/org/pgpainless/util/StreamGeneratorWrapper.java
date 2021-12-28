// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;

import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPCanonicalizedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.pgpainless.algorithm.StreamEncoding;

/**
 * Literal Data can be encoded in different ways.
 * BINARY encoding leaves the data as is and is generated through the {@link PGPLiteralDataGenerator}.
 * However, if the data is encoded in TEXT or UTF8 encoding, we need to use the {@link PGPCanonicalizedDataGenerator}
 * instead.
 *
 * This wrapper class acts as a handle for both options and provides a unified interface for them.
 */
public final class StreamGeneratorWrapper {

    private final StreamEncoding encoding;
    private final PGPLiteralDataGenerator literalDataGenerator;
    private final PGPCanonicalizedDataGenerator canonicalizedDataGenerator;

    /**
     * Create a new instance for the given encoding.
     *
     * @param encoding stream encoding
     * @return wrapper
     */
    public static StreamGeneratorWrapper forStreamEncoding(@Nonnull StreamEncoding encoding) {
        if (encoding == StreamEncoding.BINARY) {
            return new StreamGeneratorWrapper(encoding, new PGPLiteralDataGenerator());
        } else {
            return new StreamGeneratorWrapper(encoding, new PGPCanonicalizedDataGenerator());
        }
    }

    private StreamGeneratorWrapper(@Nonnull StreamEncoding encoding, @Nonnull PGPLiteralDataGenerator literalDataGenerator) {
        if (encoding != StreamEncoding.BINARY) {
            throw new IllegalArgumentException("PGPLiteralDataGenerator can only be used with BINARY encoding.");
        }
        this.encoding = encoding;
        this.literalDataGenerator = literalDataGenerator;
        this.canonicalizedDataGenerator = null;
    }

    private StreamGeneratorWrapper(@Nonnull StreamEncoding encoding, @Nonnull PGPCanonicalizedDataGenerator canonicalizedDataGenerator) {
        if (encoding != StreamEncoding.TEXT && encoding != StreamEncoding.UTF8) {
            throw new IllegalArgumentException("PGPCanonicalizedDataGenerator can only be used with TEXT or UTF8 encoding.");
        }
        this.encoding = encoding;
        this.canonicalizedDataGenerator = canonicalizedDataGenerator;
        this.literalDataGenerator = null;
    }

    /**
     * Open a new encoding stream.
     *
     * @param outputStream wrapped output stream
     * @param filename file name
     * @param modificationDate modification date
     * @param buffer buffer
     * @return encoding stream
     */
    public OutputStream open(OutputStream outputStream, String filename, Date modificationDate, byte[] buffer) throws IOException {
        if (literalDataGenerator != null) {
            return literalDataGenerator.open(outputStream, encoding.getCode(), filename, modificationDate, buffer);
        } else {
            return canonicalizedDataGenerator.open(outputStream, encoding.getCode(), filename, modificationDate, buffer);
        }
    }

    /**
     * Close all encoding streams opened by this generator wrapper.
     */
    public void close() throws IOException {
        if (literalDataGenerator != null) {
            literalDataGenerator.close();
        }
        if (canonicalizedDataGenerator != null) {
            canonicalizedDataGenerator.close();
        }
    }
}
