// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.openpgp.PGPUtil;

public final class PGPUtilWrapper {

    private PGPUtilWrapper() {

    }

    /**
     * {@link PGPUtil#getDecoderStream(InputStream)} sometimes mistakens non-base64 data for base64 encoded data.
     *
     * This method expects a {@link BufferedInputStream} which is being reset in case an {@link IOException} is encountered.
     * Therefore, we can properly handle non-base64 encoded data.
     *
     * @param buf buffered input stream
     * @return input stream
     * @throws IOException in case of an io error which is unrelated to base64 encoding
     */
    public static InputStream getDecoderStream(BufferedInputStream buf) throws IOException {
        try {
            return PGPUtil.getDecoderStream(buf);
        } catch (IOException e) {
            if (e.getMessage().contains("invalid characters encountered at end of base64 data")) {
                buf.reset();
                return buf;
            }
            throw e;
        }
    }
}
