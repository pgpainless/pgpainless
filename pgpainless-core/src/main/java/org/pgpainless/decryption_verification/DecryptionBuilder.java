// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import java.io.IOException;
import java.io.InputStream;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;

/**
 * Builder class that takes an {@link InputStream} of ciphertext (or plaintext signed data)
 * and combines it with a configured {@link ConsumerOptions} object to form a {@link DecryptionStream} which
 * can be used to decrypt an OpenPGP message or verify signatures.
 */
public class DecryptionBuilder implements DecryptionBuilderInterface {

    @Override
    public DecryptWith onInputStream(@Nonnull InputStream inputStream) {
        return new DecryptWithImpl(inputStream);
    }

    static class DecryptWithImpl implements DecryptWith {

        private final InputStream inputStream;

        DecryptWithImpl(InputStream inputStream) {
            this.inputStream = inputStream;
        }

        @Override
        public DecryptionStream withOptions(ConsumerOptions consumerOptions) throws PGPException, IOException {
            if (consumerOptions == null) {
                throw new IllegalArgumentException("Consumer options cannot be null.");
            }

            return OpenPgpMessageInputStream.create(inputStream, consumerOptions);
        }
    }
}
