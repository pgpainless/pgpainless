// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import java.util.Date;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPLiteralData;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.StreamEncoding;

public final class ProducerOptions {

    private final EncryptionOptions encryptionOptions;
    private final SigningOptions signingOptions;
    private String fileName = "";
    private Date modificationDate = PGPLiteralData.NOW;
    private StreamEncoding streamEncoding = StreamEncoding.BINARY;
    private boolean cleartextSigned = false;

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
     * Specify, whether or not the result of the encryption/signing operation shall be ascii armored.
     * The default value is true.
     *
     * @param asciiArmor ascii armor
     * @return builder
     */
    public ProducerOptions setAsciiArmor(boolean asciiArmor) {
        if (cleartextSigned && !asciiArmor) {
            throw new IllegalArgumentException("Cleartext signing is enabled. Cannot disable ASCII armoring.");
        }
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

    public ProducerOptions setCleartextSigned() {
        if (signingOptions == null) {
            throw new IllegalArgumentException("Signing Options cannot be null if cleartext signing is enabled.");
        }
        if (encryptionOptions != null) {
            throw new IllegalArgumentException("Cannot encode encrypted message as Cleartext Signed.");
        }
        for (SigningOptions.SigningMethod method : signingOptions.getSigningMethods().values()) {
            if (!method.isDetached()) {
                throw new IllegalArgumentException("For cleartext signed message, all signatures must be added as detached signatures.");
            }
        }
        cleartextSigned = true;
        asciiArmor = true;
        compressionAlgorithmOverride = CompressionAlgorithm.UNCOMPRESSED;
        return this;
    }

    public boolean isCleartextSigned() {
        return cleartextSigned;
    }

    /**
     * Set the name of the encrypted file.
     * Note: This option cannot be used simultaneously with {@link #setForYourEyesOnly()}.
     *
     * @param fileName name of the encrypted file
     * @return this
     */
    public ProducerOptions setFileName(@Nonnull String fileName) {
        this.fileName = fileName;
        return this;
    }

    /**
     * Return the encrypted files name.
     *
     * @return file name
     */
    public String getFileName() {
        return fileName;
    }

    /**
     * Mark the encrypted message as for-your-eyes-only by setting a special file name.
     * Note: Therefore this method cannot be used simultaneously with {@link #setFileName(String)}.
     *
     * @return this
     */
    public ProducerOptions setForYourEyesOnly() {
        this.fileName = PGPLiteralData.CONSOLE;
        return this;
    }

    /**
     * Set the modification date of the encrypted file.
     *
     * @param modificationDate Modification date of the encrypted file.
     * @return this
     */
    public ProducerOptions setModificationDate(@Nonnull Date modificationDate) {
        this.modificationDate = modificationDate;
        return this;
    }

    /**
     * Return the modification date of the encrypted file.
     *
     * @return modification date
     */
    public Date getModificationDate() {
        return modificationDate;
    }

    /**
     * Set the format of the literal data packet.
     * Defaults to {@link StreamEncoding#BINARY}.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.9">RFC4880 §5.9. Literal Data Packet</a>
     *
     * @param encoding encoding
     * @return this
     */
    public ProducerOptions setEncoding(@Nonnull StreamEncoding encoding) {
        this.streamEncoding = encoding;
        return this;
    }

    public StreamEncoding getEncoding() {
        return streamEncoding;
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
