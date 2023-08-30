// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification

import java.io.InputStream

/**
 * Abstract definition of an [InputStream] which can be used to decrypt / verify OpenPGP messages.
 */
abstract class DecryptionStream: InputStream() {

    /**
     * Return [MessageMetadata] about the decrypted / verified message.
     * The [DecryptionStream] MUST be closed via [close] before the metadata object can be accessed.
     *
     * @return message metadata
     */
    abstract val metadata: MessageMetadata

    /**
     * Return a [OpenPgpMetadata] object containing information about the decrypted / verified message.
     * The [DecryptionStream] MUST be closed via [close] before the metadata object can be accessed.
     *
     * @return message metadata
     * @deprecated use [metadata] instead.
     */
    @Deprecated("Use of OpenPgpMetadata is discouraged.",
            ReplaceWith("metadata"))
    val result: OpenPgpMetadata
        get() = metadata.toLegacyMetadata()
}