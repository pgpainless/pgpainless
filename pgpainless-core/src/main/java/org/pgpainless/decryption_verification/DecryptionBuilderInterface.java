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
package org.pgpainless.decryption_verification;

import java.io.IOException;
import java.io.InputStream;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;

public interface DecryptionBuilderInterface {

    /**
     * Create a {@link DecryptionStream} on an {@link InputStream} which contains the encrypted and/or signed data.
     *
     * @param inputStream encrypted and/or signed data.
     * @return api handle
     */
    DecryptWith onInputStream(@Nonnull InputStream inputStream);

    interface DecryptWith {

        /**
         * Add options for decryption / signature verification, such as keys, passphrases etc.
         *
         * @param consumerOptions consumer options
         * @return decryption stream
         * @throws PGPException in case of an OpenPGP related error
         * @throws IOException in case of an IO error
         */
        DecryptionStream withOptions(ConsumerOptions consumerOptions) throws PGPException, IOException;

    }
}
