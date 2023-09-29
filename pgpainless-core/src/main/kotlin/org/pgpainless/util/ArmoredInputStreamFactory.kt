// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util

import org.bouncycastle.bcpg.ArmoredInputStream
import java.io.IOException
import java.io.InputStream

/**
 * Factory class for instantiating preconfigured [ArmoredInputStream] instances.
 * [get] will return an [ArmoredInputStream] that is set up to properly detect CRC errors v4 style.
 */
class ArmoredInputStreamFactory {

    companion object {

        /**
         * Return an instance of [ArmoredInputStream] which will detect CRC errors.
         *
         * @param inputStream input stream
         * @return armored input stream
         * @throws IOException in case of an IO error
         */
        @JvmStatic
        @Throws(IOException::class)
        fun get(inputStream: InputStream): ArmoredInputStream {
            return when (inputStream) {
                is CRCingArmoredInputStreamWrapper -> inputStream
                is ArmoredInputStream -> CRCingArmoredInputStreamWrapper(inputStream)
                else -> CRCingArmoredInputStreamWrapper(ArmoredInputStream(inputStream))
            }
        }
    }
}