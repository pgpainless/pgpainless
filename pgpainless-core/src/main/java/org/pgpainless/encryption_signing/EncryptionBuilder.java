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
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.algorithm.negotiation.SymmetricKeyAlgorithmNegotiator;
import org.pgpainless.key.SubkeyIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EncryptionBuilder implements EncryptionBuilderInterface {

    private static final Logger LOGGER = LoggerFactory.getLogger(EncryptionBuilder.class);

    private OutputStream outputStream;

    @Override
    public WithOptions onOutputStream(@Nonnull OutputStream outputStream) {
        this.outputStream = outputStream;
        return new WithOptionsImpl();
    }

    class WithOptionsImpl implements WithOptions {
        @Override
        public EncryptionStream withOptions(ProducerOptions options) throws PGPException, IOException {
            if (options == null) {
                throw new NullPointerException("ProducerOptions cannot be null.");
            }
            return new EncryptionStream(outputStream, options);
        }
    }

    /**
     * Negotiate the {@link SymmetricKeyAlgorithm} used for message encryption.
     *
     * @param encryptionOptions encryption options
     * @return negotiated symmetric key algorithm
     */
    public static SymmetricKeyAlgorithm negotiateSymmetricEncryptionAlgorithm(EncryptionOptions encryptionOptions) {
        List<Set<SymmetricKeyAlgorithm>> preferences = new ArrayList<>();
        for (SubkeyIdentifier key : encryptionOptions.getKeyViews().keySet()) {
            preferences.add(encryptionOptions.getKeyViews().get(key).getPreferredSymmetricKeyAlgorithms());
        }

        SymmetricKeyAlgorithm algorithm = SymmetricKeyAlgorithmNegotiator
                .byPopularity()
                .negotiate(
                        PGPainless.getPolicy().getSymmetricKeyEncryptionAlgorithmPolicy(),
                        encryptionOptions.getEncryptionAlgorithmOverride(),
                        preferences);
        LOGGER.debug("Negotiation resulted in {} being the symmetric encryption algorithm of choice.", algorithm);
        return algorithm;
    }

    public static CompressionAlgorithm negotiateCompressionAlgorithm(ProducerOptions producerOptions) {
        CompressionAlgorithm compressionAlgorithmOverride = producerOptions.getCompressionAlgorithmOverride();
        if (compressionAlgorithmOverride != null) {
            return compressionAlgorithmOverride;
        }

        // TODO: Negotiation

        return PGPainless.getPolicy().getCompressionAlgorithmPolicy().defaultCompressionAlgorithm();
    }
}
