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
        buf.mark(512);
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
