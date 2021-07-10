/*
 * Copyright 2018 Paul Schaub.
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
package org.pgpainless.encryption_signing;

import java.io.IOException;
import java.io.OutputStream;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;

public interface EncryptionBuilderInterface {

    /**
     * Create a {@link EncryptionStream} on an {@link OutputStream} that contains the plain data that
     * shall be encrypted and or signed.
     *
     * @param outputStream output stream of the plain data.
     * @return api handle
     */
    WithOptions onOutputStream(@Nonnull OutputStream outputStream);

    interface WithOptions {

        /**
         * Create an {@link EncryptionStream} with the given options (recipients, signers, algorithms...).
         *
         * @param options options
         * @return encryption strea
         */
        EncryptionStream withOptions(ProducerOptions options) throws PGPException, IOException;

    }
}
