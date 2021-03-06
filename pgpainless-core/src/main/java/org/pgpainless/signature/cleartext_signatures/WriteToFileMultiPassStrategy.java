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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * File-based multi-pass strategy.
 * When processing the signed data the first time, the data is being written out into a file.
 * For the second pass, that file is being read again.
 */
public class WriteToFileMultiPassStrategy implements MultiPassStrategy {

    private final File file;

    /**
     * Create a {@link MultiPassStrategy} which writes data to a file.
     * Note that {@link #getMessageOutputStream()} will create the file if necessary.
     *
     * @param file file to write the data to and read from
     */
    public WriteToFileMultiPassStrategy(File file) {
        this.file = file;
    }

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
}
