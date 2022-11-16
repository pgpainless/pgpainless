// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import java.io.InputStream;

/**
 * Abstract definition of an {@link InputStream} which can be used to decrypt / verify OpenPGP messages.
 */
public abstract class DecryptionStream extends InputStream {

    /**
     * Return {@link MessageMetadata metadata} about the decrypted / verified message.
     * The {@link DecryptionStream} MUST be closed via {@link #close()} before the metadata object can be accessed.
     *
     * @return message metadata
     */
    public abstract MessageMetadata getMetadata();

    /**
     * Return a {@link OpenPgpMetadata} object containing information about the decrypted / verified message.
     * The {@link DecryptionStream} MUST be closed via {@link #close()} before the metadata object can be accessed.
     *
     * @return message metadata
     * @deprecated use {@link #getMetadata()} instead.
     */
    @Deprecated
    public OpenPgpMetadata getResult() {
        return getMetadata().toLegacyMetadata();
    }
}
