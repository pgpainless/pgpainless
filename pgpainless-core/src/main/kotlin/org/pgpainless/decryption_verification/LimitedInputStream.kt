// SPDX-FileCopyrightText: 2026 David Hook
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification

import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream
import org.bouncycastle.util.io.StreamOverflowException

/** Copied from BC, see [org.bouncycastle.openpgp.PGPCompressedData.LimitedInputStream]. */
internal class LimitedInputStream(input: InputStream, limit: Long) : FilterInputStream(input) {
    private var remaining: Long = limit

    @Throws(IOException::class)
    override fun read(): Int {
        // Only a single 'extra' byte will ever be read
        if (remaining >= 0) {
            val b = super.`in`.read()
            if (b < 0 || --remaining >= 0) {
                return b
            }
        }

        throw StreamOverflowException(
            "Decompressed data limit exceeded. " +
                "You may increase the limit using Policy.copy().withMaxDecompressedDataSize(yourLimit)")
    }

    @Throws(IOException::class)
    override fun read(buf: ByteArray, off: Int, len: Int): Int {
        if (len < 1) {
            // This will give correct exceptions/returns for strange lengths
            return super.read(buf, off, len)
        }

        if (remaining < 1) {
            // Will either return EOF or throw exception
            read()
            return -1
        }

        /*
         * Limit the underlying request to 'remaining' bytes. This ensures the
         * caller will see the full 'limit' bytes before getting an exception.
         * Also, only one extra byte will ever be read.
         */
        val actualLen = if (remaining > len) len else remaining.toInt()
        val numRead = super.`in`.read(buf, off, actualLen)
        if (numRead > 0) {
            remaining -= numRead.toLong()
        }
        return numRead
    }
}
