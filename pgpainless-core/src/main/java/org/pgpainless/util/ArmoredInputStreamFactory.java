// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.bcpg.ArmoredInputStream;

/**
 * Factory class for instantiating preconfigured {@link ArmoredInputStream ArmoredInputStreams}.
 * {@link #get(InputStream)} will return an {@link ArmoredInputStream} that is set up to properly detect CRC errors.
 */
public final class ArmoredInputStreamFactory {

    private ArmoredInputStreamFactory() {

    }

    /**
     * Return an instance of {@link ArmoredInputStream} which will detect CRC errors.
     *
     * @param inputStream input stream
     * @return armored input stream
     * @throws IOException in case of an IO error
     */
    public static ArmoredInputStream get(InputStream inputStream) throws IOException {
        if (inputStream instanceof CRCingArmoredInputStreamWrapper) {
            return (ArmoredInputStream) inputStream;
        }
        if (inputStream instanceof ArmoredInputStream) {
            return new CRCingArmoredInputStreamWrapper((ArmoredInputStream) inputStream);
        }

        ArmoredInputStream armorIn = new ArmoredInputStream(inputStream);
        return new CRCingArmoredInputStreamWrapper(armorIn);
    }
}
