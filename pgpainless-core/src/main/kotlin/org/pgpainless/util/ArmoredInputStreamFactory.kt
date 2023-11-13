// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util

import java.io.IOException
import java.io.InputStream
import org.bouncycastle.bcpg.ArmoredInputStream
import org.pgpainless.decryption_verification.ConsumerOptions

/**
 * Factory class for instantiating preconfigured [ArmoredInputStream] instances. [get] will return
 * an [ArmoredInputStream] that is set up to properly detect CRC errors v4 style.
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
        @JvmOverloads
        @Throws(IOException::class)
        fun get(inputStream: InputStream, options: ConsumerOptions? = null): ArmoredInputStream {
            return when (inputStream) {
                is ArmoredInputStream -> inputStream
                else ->
                    ArmoredInputStream.builder()
                        .apply {
                            setParseForHeaders(true)
                            options?.let { setIgnoreCRC(it.isDisableAsciiArmorCRC) }
                        }
                        .build(inputStream)
            }
        }
    }
}
