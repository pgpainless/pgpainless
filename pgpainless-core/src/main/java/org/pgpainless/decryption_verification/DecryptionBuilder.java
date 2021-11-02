// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;
import org.pgpainless.decryption_verification.cleartext_signatures.VerifyCleartextSignaturesImpl;
import org.pgpainless.exception.WrongConsumingMethodException;

public class DecryptionBuilder implements DecryptionBuilderInterface {

    public static int BUFFER_SIZE = 4096;

    @Override
    public DecryptWith onInputStream(@Nonnull InputStream inputStream) {
        return new DecryptWithImpl(inputStream);
    }

    class DecryptWithImpl implements DecryptWith {

        private BufferedInputStream inputStream;

        DecryptWithImpl(InputStream inputStream) {
            this.inputStream = new BufferedInputStream(inputStream, BUFFER_SIZE);
            this.inputStream.mark(BUFFER_SIZE);
        }

        @Override
        public DecryptionStream withOptions(ConsumerOptions consumerOptions) throws PGPException, IOException {
            if (consumerOptions == null) {
                throw new IllegalArgumentException("Consumer options cannot be null.");
            }

            try {
                return DecryptionStreamFactory.create(inputStream, consumerOptions);
            } catch (WrongConsumingMethodException e) {
                inputStream.reset();
                return new VerifyCleartextSignaturesImpl()
                        .onInputStream(inputStream)
                        .withOptions(consumerOptions)
                        .getVerificationStream();
            }
        }
    }
}
