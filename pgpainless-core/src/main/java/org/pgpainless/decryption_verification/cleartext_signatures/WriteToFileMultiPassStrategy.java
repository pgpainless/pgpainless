// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.cleartext_signatures;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Implementation of the {@link MultiPassStrategy}.
 * When processing signed data the first time, the data is being written out into a file.
 * For the second pass, that file is being read again.
 *
 * This strategy is recommended when larger amounts of data need to be processed.
 * For smaller files, {@link InMemoryMultiPassStrategy} yields higher efficiency.
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
