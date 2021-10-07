// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import java.io.IOException;
import java.io.InputStream;
import javax.annotation.Nonnull;

public abstract class CloseForResultInputStream extends InputStream {

    protected final OpenPgpMetadata.Builder resultBuilder;
    private boolean isClosed = false;

    public CloseForResultInputStream(@Nonnull OpenPgpMetadata.Builder resultBuilder) {
        this.resultBuilder = resultBuilder;
    }

    @Override
    public void close() throws IOException {
        this.isClosed = true;
    }

    /**
     * Return the result of the decryption.
     * The result contains metadata about the decryption, such as signatures, used keys and algorithms, as well as information
     * about the decrypted file/stream.
     *
     * Can only be obtained once the stream got successfully closed ({@link #close()}).
     * @return metadata
     */
    public OpenPgpMetadata getResult() {
        if (!isClosed) {
            throw new IllegalStateException("Stream MUST be closed before the result can be accessed.");
        }
        return resultBuilder.build();
    }
}
