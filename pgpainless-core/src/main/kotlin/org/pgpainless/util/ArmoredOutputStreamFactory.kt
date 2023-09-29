// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.pgpainless.encryption_signing.ProducerOptions
import java.io.OutputStream

/**
 * Factory to create configured [ArmoredOutputStream] instances.
 * The configuration entails setting custom version and comment headers.
 */
class ArmoredOutputStreamFactory {

    companion object {
        private const val PGPAINLESS = "PGPainless"

        @JvmStatic
        private var version: String? = PGPAINLESS
        private var comment: String? = null

        /**
         * Return an instance of the [ArmoredOutputStream] which might have pre-populated armor headers.
         *
         * @param outputStream output stream
         * @param options options
         * @return armored output stream
         */
        @JvmStatic
        @JvmOverloads
        fun get(outputStream: OutputStream, options: ProducerOptions? = null): ArmoredOutputStream {
            val builder = ArmoredOutputStream.builder().apply {
                // set fields defined in ArmoredOutputStreamFactory
                if (!version.isNullOrBlank()) setVersion(version)
                if (!comment.isNullOrBlank()) setComment(comment)

                // set (and potentially overwrite with) values from ProducerOptions
                options?.let {
                    enableCRC(!it.isDisableAsciiArmorCRC)
                    if (it.isHideArmorHeaders) clearHeaders()
                    if (it.hasVersion()) setVersion(it.version)
                    if (it.hasComment()) addComment(it.comment)
                    // TODO: configure CRC
                }
            }
            return get(outputStream, builder)
        }

        /**
         * Build an [ArmoredOutputStream] around the given [outputStream], configured according to the passed in
         * [ArmoredOutputStream.Builder] instance.
         *
         * @param outputStream output stream
         * @param builder builder instance
         */
        @JvmStatic
        fun get(outputStream: OutputStream, builder: ArmoredOutputStream.Builder): ArmoredOutputStream {
            return builder.build(outputStream)
        }

        /**
         * Overwrite the version header of ASCII armors with a custom value.
         * Newlines in the version info string result in multiple version header entries.
         * If this is set to <pre>null</pre>, then the version header is omitted altogether.
         *
         * @param versionString version string
         */
        @JvmStatic
        fun setVersionInfo(versionString: String?) {
            version = if (versionString.isNullOrBlank()) null else versionString.trim()
        }

        /**
         * Reset the version header to its default value of [PGPAINLESS].
         */
        @JvmStatic
        fun resetVersionInfo() {
            version = PGPAINLESS
        }

        /**
         * Set a comment header value in the ASCII armor header.
         * If the comment contains newlines, it will be split into multiple header entries.
         *
         * @see [ProducerOptions.setComment] for how to set comments for individual messages.
         *
         * @param commentString comment
         */
        @JvmStatic
        fun setComment(commentString: String) {
            require(commentString.isNotBlank()) { "Comment cannot be empty. See resetComment() to clear the comment." }
            comment = commentString.trim()
        }

        @JvmStatic
        fun resetComment() {
            comment = null
        }
    }
}