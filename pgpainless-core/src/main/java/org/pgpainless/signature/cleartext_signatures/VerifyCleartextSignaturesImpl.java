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
package org.pgpainless.signature.cleartext_signatures;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
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

        @Override
        public CleartextSignatureProcessor verifyWith(PGPPublicKeyRing publicKey) throws IOException {
            ConsumerOptions options = new ConsumerOptions();
            options.addVerificationCert(publicKey);
            return new CleartextSignatureProcessor(inputStream, options, multiPassStrategy);
        }

        @Override
        public CleartextSignatureProcessor verifyWith(PGPPublicKeyRingCollection publicKeys) throws IOException {
            ConsumerOptions options = new ConsumerOptions();
            options.addVerificationCerts(publicKeys);
            return new CleartextSignatureProcessor(inputStream, options, multiPassStrategy);
        }
    }
}
