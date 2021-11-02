// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.cleartext_signatures;

import java.io.IOException;
import java.io.InputStream;

import org.pgpainless.decryption_verification.ConsumerOptions;

/**
 * Interface defining the API for verification of cleartext signed documents.
 */
public interface VerifyCleartextSignatures {

    /**
     * Provide the {@link InputStream} which contains the cleartext-signed message.
     * @param inputStream inputstream
     * @return api handle
     */
    VerifyWith onInputStream(InputStream inputStream);

    interface VerifyWith {

        /**
         * Pass in consumer options like verification certificates, acceptable date ranges etc.
         *
         * @param options options
         * @return processor
         * @throws IOException in case of an IO error
         */
        CleartextSignatureProcessor withOptions(ConsumerOptions options) throws IOException;

    }
}
