// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.cleartext_signatures

import java.io.*

/**
 * Implementation of the [MultiPassStrategy]. When processing signed data the first time, the data
 * is being written out into a file. For the second pass, that file is being read again.
 *
 * This strategy is recommended when larger amounts of data need to be processed. For smaller files,
 * [InMemoryMultiPassStrategy] yields higher efficiency.
 *
 * @param file file to write the data to and read from
 */
class WriteToFileMultiPassStrategy(private val file: File) : MultiPassStrategy {

    override val messageOutputStream: OutputStream
        @Throws(IOException::class)
        get() {
            if (!file.exists()) {
                if (!file.createNewFile()) {
                    throw IOException("New file '${file.absolutePath}' could not be created.")
                }
            }
            return FileOutputStream(file)
        }

    override val messageInputStream: InputStream
        @Throws(IOException::class)
        get() {
            if (!file.exists()) {
                throw IOException("File '${file.absolutePath}' does no longer exist.")
            }
            return FileInputStream(file)
        }
}
