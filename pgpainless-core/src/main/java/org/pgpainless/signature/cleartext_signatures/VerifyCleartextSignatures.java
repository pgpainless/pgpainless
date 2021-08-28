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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
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
    WithStrategy onInputStream(InputStream inputStream);

    interface WithStrategy {

        /**
         * Provide a {@link MultiPassStrategy} which is used to store the message content.
         * Since cleartext-signed messages cannot be processed in one pass, the message has to be passed twice.
         * Therefore the user needs to decide upon a strategy where to cache/store the message between the passes.
         * This could be {@link MultiPassStrategy#writeMessageToFile(File)} or {@link MultiPassStrategy#keepMessageInMemory()},
         * depending on message size and use-case.
         *
         * @param multiPassStrategy strategy
         * @return api handle
         */
        VerifyWith withStrategy(MultiPassStrategy multiPassStrategy);

    }

    interface VerifyWith {

        /**
         * Pass in consumer options like verification certificates, acceptable date ranges etc.
         *
         * @param options options
         * @return processor
         * @throws IOException in case of an IO error
         */
        CleartextSignatureProcessor withOptions(ConsumerOptions options) throws IOException;

        /**
         * Pass in the verification key ring.
         *
         * @param publicKey verification key
         * @return processor
         * @throws PGPException if the keys cannot be converted to a {@link PGPPublicKeyRingCollection}.
         * @throws IOException if the keys cannot be parsed properly
         *
         * @deprecated use {@link #withOptions(ConsumerOptions)} instead.
         */
        @Deprecated
        CleartextSignatureProcessor verifyWith(PGPPublicKeyRing publicKey) throws PGPException, IOException;

        /**
         * Pass in the verification key ring collection.
         *
         * @param publicKeys verification keys
         * @return processor
         * @throws IOException if the keys cannot be parsed properly
         *
         * @deprecated use {@link #withOptions(ConsumerOptions)} instead.
         */
        @Deprecated
        CleartextSignatureProcessor verifyWith(PGPPublicKeyRingCollection publicKeys) throws IOException;

    }
}
