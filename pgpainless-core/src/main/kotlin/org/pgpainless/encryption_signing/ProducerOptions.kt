// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing

import java.util.*
import org.bouncycastle.openpgp.PGPLiteralData
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.algorithm.StreamEncoding

class ProducerOptions(
    val encryptionOptions: EncryptionOptions?,
    val signingOptions: SigningOptions?,
    val api: PGPainless = PGPainless.getInstance()
) {

    private var _fileName: String = ""
    private var _modificationDate: Date = PGPLiteralData.NOW
    private var encodingField: StreamEncoding = StreamEncoding.BINARY
    private var applyCRLFEncoding = false
    private var cleartextSigned = false
    private var _hideArmorHeaders = false
    var isDisableAsciiArmorCRC = false

    private var _compressionAlgorithmOverride: CompressionAlgorithm =
        api.algorithmPolicy.compressionAlgorithmPolicy.defaultCompressionAlgorithm
    private var asciiArmor = true
    private var _comment: String? = null
    private var _version: String? = null

    /**
     * Specify, whether the result of the encryption/signing operation shall be ascii armored. The
     * default value is true.
     *
     * @param asciiArmor ascii armor
     * @return builder
     */
    fun setAsciiArmor(asciiArmor: Boolean) = apply {
        require(!(cleartextSigned && !asciiArmor)) {
            "Cleartext signing is enabled. Cannot disable ASCII armoring."
        }
        this.asciiArmor = asciiArmor
    }

    /**
     * Return true if the output of the encryption/signing operation shall be ascii armored.
     *
     * @return ascii armored
     */
    val isAsciiArmor: Boolean
        get() = asciiArmor

    /**
     * Set the comment header in ASCII armored output. The default value is null, which means no
     * comment header is added. Multiline comments are possible using '\\n'. <br> Note: If a default
     * header comment is set using [org.pgpainless.util.ArmoredOutputStreamFactory.setComment], then
     * both comments will be written to the produced ASCII armor.
     *
     * @param comment comment header text
     * @return builder
     */
    fun setComment(comment: String?) = apply { _comment = comment }

    /**
     * Return comment set for header in ascii armored output.
     *
     * @return comment
     */
    val comment: String?
        get() = _comment

    /**
     * Return whether a comment was set (!= null).
     *
     * @return true if commend is set
     */
    fun hasComment() = _comment != null

    /**
     * Set the version header in ASCII armored output. The default value is null, which means no
     * version header is added. <br> Note: If the value is non-null, then this method overrides the
     * default version header set using
     * [org.pgpainless.util.ArmoredOutputStreamFactory.setVersionInfo].
     *
     * @param version version header, or null for no version info.
     * @return builder
     */
    fun setVersion(version: String?) = apply { _version = version }

    /**
     * Return the version info header in ascii armored output.
     *
     * @return version info
     */
    val version: String?
        get() = _version

    /**
     * Return whether a version header was set (!= null).
     *
     * @return true if version header is set
     */
    fun hasVersion() = version != null

    /**
     * Configure the resulting OpenPGP message to make use of the Cleartext Signature Framework
     * (CSF). A CSF message MUST be signed using detached signatures only and MUST NOT be encrypted.
     *
     * @see
     *   [RFC9580: OpenPGP - Cleartext Signature Framework](https://www.rfc-editor.org/rfc/rfc9580.html#name-cleartext-signature-framewo)
     */
    fun setCleartextSigned() = apply {
        require(signingOptions != null) {
            "Signing Options cannot be null if cleartext signing is enabled."
        }
        require(encryptionOptions == null) {
            "Cannot encode encrypted message as Cleartext Signed."
        }
        require(signingOptions.signingMethods.values.all { it.isDetached }) {
            "For cleartext signed messages, all signatures must be added as detached signatures."
        }

        cleartextSigned = true
        asciiArmor = true
        _compressionAlgorithmOverride = CompressionAlgorithm.UNCOMPRESSED
    }

    val isCleartextSigned: Boolean
        get() = cleartextSigned

    /**
     * Set the name of the encrypted file. Note: This option cannot be used simultaneously with
     * [setForYourEyesOnly].
     *
     * @param fileName name of the encrypted file
     * @return this
     */
    fun setFileName(fileName: String) = apply { _fileName = fileName }

    /**
     * Return the encrypted files name.
     *
     * @return file name
     */
    val fileName: String
        get() = _fileName

    /**
     * Mark the encrypted message as for-your-eyes-only by setting a special file name. Note:
     * Therefore this method cannot be used simultaneously with [setFileName].
     *
     * @return this
     * @deprecated deprecated since at least crypto-refresh-05. It is not recommended using this
     *   special filename in newly generated literal data packets
     */
    @Deprecated("Signaling using special file name is discouraged.")
    fun setForYourEyesOnly() = apply { _fileName = PGPLiteralData.CONSOLE }

    /**
     * Set the modification date of the encrypted file.
     *
     * @param modificationDate Modification date of the encrypted file.
     * @return this
     */
    fun setModificationDate(modificationDate: Date) = apply { _modificationDate = modificationDate }

    /**
     * Return the modification date of the encrypted file.
     *
     * @return modification date
     */
    val modificationDate: Date
        get() = _modificationDate

    /**
     * Set format metadata field of the literal data packet. Defaults to [StreamEncoding.BINARY].
     * <br> This does not change the encoding of the wrapped data itself. To apply CR/LF encoding to
     * your input data before processing, use [applyCRLFEncoding] instead.
     *
     * @param encoding encoding
     * @return this
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.9">RFC4880 §5.9.
     *   Literal Data Packet</a>
     * @deprecated options other than the default value of [StreamEncoding.BINARY] are discouraged.
     */
    @Deprecated("Options other than BINARY are discouraged.")
    fun setEncoding(encoding: StreamEncoding) = apply { encodingField = encoding }

    val encoding: StreamEncoding
        get() = encodingField

    /**
     * Apply special encoding of line endings to the input data. By default, this is disabled, which
     * means that the data is not altered. <br> Enabling it will change the line endings to CR/LF.
     * Note: The encoding will not be reversed when decrypting, so applying CR/LF encoding will
     * result in the identity "decrypt(encrypt(data)) == data == verify(sign(data))".
     *
     * @return this
     */
    fun applyCRLFEncoding() = apply { applyCRLFEncoding = true }

    /**
     * Return the input encoding that will be applied before signing / encryption.
     *
     * @return input encoding
     */
    val isApplyCRLFEncoding: Boolean
        get() = applyCRLFEncoding

    /**
     * Override which compression algorithm shall be used.
     *
     * @param compressionAlgorithm compression algorithm override
     * @return builder
     */
    fun overrideCompressionAlgorithm(compressionAlgorithm: CompressionAlgorithm) = apply {
        _compressionAlgorithmOverride = compressionAlgorithm
    }

    val compressionAlgorithmOverride: CompressionAlgorithm
        get() = _compressionAlgorithmOverride

    val isHideArmorHeaders: Boolean
        get() = _hideArmorHeaders

    /**
     * If set to `true`, armor headers like version or comments will be omitted from armored output.
     * By default, armor headers are not hidden. Note: If comments are added via [setComment], those
     * are not omitted, even if [hideArmorHeaders] is set to `true`.
     *
     * @param hideArmorHeaders true or false
     * @return this
     */
    fun setHideArmorHeaders(hideArmorHeaders: Boolean) = apply {
        _hideArmorHeaders = hideArmorHeaders
    }

    internal fun negotiateCompressionAlgorithm(): CompressionAlgorithm {
        return compressionAlgorithmOverride
    }

    companion object {
        /**
         * Sign and encrypt some data.
         *
         * @param encryptionOptions encryption options
         * @param signingOptions signing options
         * @return builder
         */
        @JvmStatic
        fun signAndEncrypt(encryptionOptions: EncryptionOptions, signingOptions: SigningOptions) =
            ProducerOptions(encryptionOptions, signingOptions)

        /**
         * Sign some data without encryption.
         *
         * @param signingOptions signing options
         * @return builder
         */
        @JvmStatic fun sign(signingOptions: SigningOptions) = ProducerOptions(null, signingOptions)

        /**
         * Encrypt some data without signing.
         *
         * @param encryptionOptions encryption options
         * @return builder
         */
        @JvmStatic
        fun encrypt(encryptionOptions: EncryptionOptions) = ProducerOptions(encryptionOptions, null)

        /**
         * Only wrap the data in an OpenPGP packet. No encryption or signing will be applied.
         *
         * @return builder
         */
        @JvmStatic fun noEncryptionNoSigning() = ProducerOptions(null, null)
    }
}
