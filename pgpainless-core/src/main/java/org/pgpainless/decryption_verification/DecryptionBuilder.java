// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import java.io.IOException;
import java.io.InputStream;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;

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
