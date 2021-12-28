// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.cleartext_signatures;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Since the {@link CleartextSignatureProcessor} needs to read the whole data twice in order to verify signatures,
 * a strategy for how to cache the read data is required.
 * Otherwise, large data kept in memory could cause {@link OutOfMemoryError OutOfMemoryErrors} or other issues.
 *
 * This is an Interface that describes a strategy to deal with the fact that detached signatures require multiple passes
 * to do verification.
 *
 * This interface can be used to write the signed data stream out via {@link #getMessageOutputStream()} and later
 * get access to the data again via {@link #getMessageInputStream()}.
 * Thereby the detail where the data is being stored (memory, file, etc.) can be abstracted away.
 */
public interface MultiPassStrategy {

    /**
     * Provide an {@link OutputStream} into which the signed data can be read into.
     *
     * @return output stream
     * @throws IOException io error
     */
    OutputStream getMessageOutputStream() throws IOException;

    /**
     * Provide an {@link InputStream} which contains the data that was previously written away in
     * {@link #getMessageOutputStream()}.
     *
     * As there may be multiple signatures that need to be processed, each call of this method MUST return
     * a new {@link InputStream}.
     *
     * @return input stream
     * @throws IOException io error
     */
    InputStream getMessageInputStream() throws IOException;

    /**
     * Write the message content out to a file and re-read it to verify signatures.
     * This strategy is best suited for larger messages (e.g. plaintext signed files) which might not fit into memory.
     * After the message has been processed completely, the messages content are available at the provided file.
     *
     * @param file target file
     * @return strategy
     */
    static MultiPassStrategy writeMessageToFile(File file) {
        return new WriteToFileMultiPassStrategy(file);
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
