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
package org.pgpainless.encryption_signing;

import javax.annotation.Nullable;

import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;

public final class ProducerOptions {

    private final EncryptionOptions encryptionOptions;
    private final SigningOptions signingOptions;

    private CompressionAlgorithm compressionAlgorithmOverride = PGPainless.getPolicy().getCompressionAlgorithmPolicy()
            .defaultCompressionAlgorithm();
    private boolean asciiArmor = true;

    private ProducerOptions(EncryptionOptions encryptionOptions, SigningOptions signingOptions) {
        this.encryptionOptions = encryptionOptions;
        this.signingOptions = signingOptions;
    }

    /**
     * Sign and encrypt some data.
     *
     * @param encryptionOptions encryption options
     * @param signingOptions signing options
     * @return builder
     */
    public static ProducerOptions signAndEncrypt(EncryptionOptions encryptionOptions,
                                                 SigningOptions signingOptions) {
        throwIfNull(encryptionOptions);
        throwIfNull(signingOptions);
        return new ProducerOptions(encryptionOptions, signingOptions);
    }

    /**
     * Sign some data without encryption.
     *
     * @param signingOptions signing options
     * @return builder
     */
    public static ProducerOptions sign(SigningOptions signingOptions) {
        throwIfNull(signingOptions);
        return new ProducerOptions(null, signingOptions);
    }

    /**
     * Encrypt some data without signing.
     *
     * @param encryptionOptions encryption options
     * @return builder
     */
    public static ProducerOptions encrypt(EncryptionOptions encryptionOptions) {
        throwIfNull(encryptionOptions);
        return new ProducerOptions(encryptionOptions, null);
    }

    public static ProducerOptions noEncryptionNoSigning() {
        return new ProducerOptions(null, null);
    }

    private static void throwIfNull(EncryptionOptions encryptionOptions) {
        if (encryptionOptions == null) {
            throw new NullPointerException("EncryptionOptions cannot be null.");
        }
    }

    private static void throwIfNull(SigningOptions signingOptions) {
        if (signingOptions == null) {
            throw new NullPointerException("SigningOptions cannot be null.");
        }
    }

    /**
     * Override which compression algorithm shall be used.
     *
     * @param compressionAlgorithm compression algorithm override
     * @return builder
     */
    public ProducerOptions overrideCompressionAlgorithm(CompressionAlgorithm compressionAlgorithm) {
        if (compressionAlgorithm == null) {
            throw new NullPointerException("Compression algorithm cannot be null.");
        }
        this.compressionAlgorithmOverride = compressionAlgorithm;
        return this;
    }

    /**
     * Specify, whether or not the result of the encryption/signing operation shall be ascii armored.
     * The default value is true.
     *
     * @param asciiArmor ascii armor
     * @return builder
     */
    public ProducerOptions setAsciiArmor(boolean asciiArmor) {
        this.asciiArmor = asciiArmor;
        return this;
    }

    /**
     * Return true if the output of the encryption/signing operation shall be ascii armored.
     *
     * @return ascii armored
     */
    public boolean isAsciiArmor() {
        return asciiArmor;
    }

    public CompressionAlgorithm getCompressionAlgorithmOverride() {
        return compressionAlgorithmOverride;
    }

    public @Nullable EncryptionOptions getEncryptionOptions() {
        return encryptionOptions;
    }

    public @Nullable SigningOptions getSigningOptions() {
        return signingOptions;
    }
}
