// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification

import java.io.InputStream

/**
 * Abstract definition of an [InputStream] which can be used to decrypt / verify OpenPGP messages.
 */
abstract class DecryptionStream : InputStream() {

    /**
     * Return [MessageMetadata] about the decrypted / verified message.
     * Note: The metadata only applies to the output of this [DecryptionStream]!
     * That means, signatures that are reported as valid only apply to the data
     * that is emitted by the stream, which is not necessarily the data that you passed
     * into the stream as input.
     *
     * @return message metadata
     */
    abstract val metadata: MessageMetadata
}
