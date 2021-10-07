// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.cleartext_signatures;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

/**
 * Implementation of the {@link MultiPassStrategy}.
 * This class keeps the read data in memory by caching the data inside a {@link ByteArrayOutputStream}.
 *
 * Note, that this class is suitable and efficient for processing small amounts of data.
 * For larger data like encrypted files, use of the {@link WriteToFileMultiPassStrategy} is recommended to
 * prevent {@link OutOfMemoryError OutOfMemoryErrors} and other issues.
 */
public class InMemoryMultiPassStrategy implements MultiPassStrategy {

    private final ByteArrayOutputStream cache = new ByteArrayOutputStream();

    @Override
    public ByteArrayOutputStream getMessageOutputStream() {
        return cache;
    }

    @Override
    public ByteArrayInputStream getMessageInputStream() {
        return new ByteArrayInputStream(getBytes());
    }

    public byte[] getBytes() {
        return getMessageOutputStream().toByteArray();
    }
}
