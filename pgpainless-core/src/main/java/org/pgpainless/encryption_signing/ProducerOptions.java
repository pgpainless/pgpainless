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
    private StreamEncoding encodingField = StreamEncoding.BINARY;
    private boolean applyCRLFEncoding = false;
    private boolean cleartextSigned = false;
    private boolean hideArmorHeaders = false;

    private CompressionAlgorithm compressionAlgorithmOverride = PGPainless.getPolicy().getCompressionAlgorithmPolicy()
            .defaultCompressionAlgorithm();
    private boolean asciiArmor = true;
    private String comment = null;

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

    /**
     * Only wrap the data in an OpenPGP packet.
     * No encryption or signing will be applied.
     *
     * @return builder
     */
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
     * Specify, whether the result of the encryption/signing operation shall be ascii armored.
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

    /**
     * Set the comment header in ASCII armored output.
     * The default value is null, which means no comment header is added.
     * Multiline comments are possible using '\\n'.
     *
     * Note: If a default header comment is set using {@link org.pgpainless.util.ArmoredOutputStreamFactory#setComment(String)},
     * then both comments will be written to the produced ASCII armor.
     *
     * @param comment comment header text
     * @return builder
     */
    public ProducerOptions setComment(String comment) {
        if (!asciiArmor) {
            throw new IllegalArgumentException("Comment can only be set when ASCII armoring is enabled.");
        }
        this.comment = comment;
        return this;
    }

    /**
     * Return comment set for header in ascii armored output.
     *
     * @return comment
     */
    public String getComment() {
        return comment;
    }

    /**
     * Return whether a comment was set (!= null).
     *
     * @return comment
     */
    public boolean hasComment() {
        return comment != null;
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
     * @deprecated deprecated since at least crypto-refresh-05. It is not recommended using this special filename in
     * newly generated literal data packets
     */
    @Deprecated
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
     * Set format metadata field of the literal data packet.
     * Defaults to {@link StreamEncoding#BINARY}.
     *
     * This does not change the encoding of the wrapped data itself.
     * To apply CR/LF encoding to your input data before processing, use {@link #applyCRLFEncoding()} instead.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.9">RFC4880 §5.9. Literal Data Packet</a>
     *
     * @param encoding encoding
     * @return this
     *
     * @deprecated options other than the default value of {@link StreamEncoding#BINARY} are discouraged.
     */
    @Deprecated
    // is used to be compatible with legacy systems
    public ProducerOptions setEncoding(@Nonnull StreamEncoding encoding) {
        this.encodingField = encoding;
        return this;
    }

    public StreamEncoding getEncoding() {
        return encodingField;
    }

    /**
     * Apply special encoding of line endings to the input data.
     * By default, this is disabled, which means that the data is not altered.
     *
     * Enabling it will change the line endings to CR/LF.
     * Note: The encoding will not be reversed when decrypting, so applying CR/LF encoding will result in
     * the identity "decrypt(encrypt(data)) == data == verify(sign(data))".
     *
     * @return this
     */
    public ProducerOptions applyCRLFEncoding() {
        this.applyCRLFEncoding = true;
        return this;
    }

    /**
     * Return the input encoding that will be applied before signing / encryption.
     *
     * @return input encoding
     */
    public boolean isApplyCRLFEncoding() {
        return applyCRLFEncoding;
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

    public boolean isHideArmorHeaders() {
        return hideArmorHeaders;
    }

    /**
     * If set to <pre>true</pre>, armor headers like version or comments will be omitted from armored output.
     * By default, armor headers are not hidden.
     * Note: If comments are added via {@link #setComment(String)}, those are not omitted, even if
     * {@link #hideArmorHeaders} is set to <pre>true</pre>.
     *
     * @param hideArmorHeaders true or false
     * @return this
     */
    public ProducerOptions setHideArmorHeaders(boolean hideArmorHeaders) {
        this.hideArmorHeaders = hideArmorHeaders;
        return this;
    }
}
