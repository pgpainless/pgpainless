// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification.cleartext_signatures;

import java.io.IOException;
import java.io.InputStream;

import org.pgpainless.decryption_verification.ConsumerOptions;

public class VerifyCleartextSignaturesImpl implements VerifyCleartextSignatures {

    private InputStream inputStream;
    private MultiPassStrategy multiPassStrategy;

    @Override
    public WithStrategy onInputStream(InputStream inputStream) {
        VerifyCleartextSignaturesImpl.this.inputStream = inputStream;
        return new WithStrategyImpl();
    }

    public class WithStrategyImpl implements WithStrategy {

        @Override
        public VerifyWith withStrategy(MultiPassStrategy multiPassStrategy) {
            if (multiPassStrategy == null) {
                throw new NullPointerException("MultiPassStrategy cannot be null.");
            }
            VerifyCleartextSignaturesImpl.this.multiPassStrategy = multiPassStrategy;
            return new VerifyWithImpl();
        }
    }

    public class VerifyWithImpl implements VerifyWith {

        @Override
        public CleartextSignatureProcessor withOptions(ConsumerOptions options) throws IOException {
            return new CleartextSignatureProcessor(inputStream, options, multiPassStrategy);
        }

    }
}
