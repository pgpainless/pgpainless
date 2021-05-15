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
package org.pgpainless.signature.cleartext_signatures;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface MultiPassStrategy {

    OutputStream getMessageOutputStream() throws IOException;

    InputStream getMessageInputStream() throws IOException;

    /**
     * Write the message content out to a file and re-read it to verify signatures.
     * This strategy is best suited for larger messages (eg. plaintext signed files) which might not fit into memory.
     * After the message has been processed completely, the messages content are available at the provided file.
     *
     * @param file target file
     * @return strategy
     */
    static MultiPassStrategy writeMessageToFile(File file) {

        return new MultiPassStrategy() {
            @Override
            public OutputStream getMessageOutputStream() throws IOException {
                if (!file.exists()) {
                    boolean created = file.createNewFile();
                    if (!created) {
                        throw new IOException("New file '" + file.getAbsolutePath() + "' was not created.");
                    }
                }
                return new FileOutputStream(file);
            }

            @Override
            public InputStream getMessageInputStream() throws IOException {
                if (!file.exists()) {
                    throw new IOException("File '" + file.getAbsolutePath() + "' does no longer exist.");
                }
                return new FileInputStream(file);
            }
        };
    }

    /**
     * Read the message content into memory.
     * This strategy is best suited for small messages which fit into memory.
     * After the message has been processed completely, the message content can be accessed by calling
     * {@link ByteArrayOutputStream#toByteArray()} on {@link #getMessageOutputStream()}.
     *
     * @return strategy
     */
    static InMemoryMultiPassStrategy keepMessageInMemory() {
        return new InMemoryMultiPassStrategy();
    }
}
