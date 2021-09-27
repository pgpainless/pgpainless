/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
