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

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.pgpainless.exception.ModificationDetectionException;

public class IntegrityProtectedInputStream extends InputStream {

    private final InputStream inputStream;
    private final PGPEncryptedData encryptedData;

    public IntegrityProtectedInputStream(InputStream inputStream, PGPEncryptedData encryptedData) {
        this.inputStream = inputStream;
        this.encryptedData = encryptedData;
    }

    @Override
    public int read() throws IOException {
        return inputStream.read();
    }

    @Override
    public void close() throws IOException {
        if (encryptedData.isIntegrityProtected()) {
            try {
                if (!encryptedData.verify()) {
                    throw new ModificationDetectionException();
                }
            } catch (PGPException e) {
                throw new IOException("Failed to verify integrity protection", e);
            }
        }
    }
}
