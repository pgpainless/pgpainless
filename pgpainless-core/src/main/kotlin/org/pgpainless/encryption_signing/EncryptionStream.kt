// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing

import java.io.BufferedOutputStream
import java.io.IOException
import java.io.OutputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.BCPGOutputStream
import org.bouncycastle.openpgp.PGPCompressedDataGenerator
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.api.MessageEncryptionMechanism
import org.bouncycastle.openpgp.api.OpenPGPSignature.OpenPGPDocumentSignature
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.algorithm.StreamEncoding
import org.pgpainless.bouncycastle.extensions.pgpDataEncryptorBuilder
import org.pgpainless.util.ArmoredOutputStreamFactory
import org.pgpainless.util.SessionKey

// 1 << 8 causes wrong partial body length encoding
//  1 << 9 fixes this.
//  see https://github.com/pgpainless/pgpainless/issues/160
const val BUFFER_SIZE = 1 shl 9

/**
 * OutputStream that produces an OpenPGP message. The message can be encrypted, signed, or both,
 * depending on its configuration.
 *
 * This class was originally based upon Jens Neuhalfen's Bouncy-GPG PGPEncryptingStream.
 *
 * @see
 *   [PGPEncryptingStream](https://github.com/neuhalje/bouncy-gpg/blob/master/src/main/java/name/neuhalfen/projects/crypto/bouncycastle/openpgp/encrypting/PGPEncryptingStream.java)
 */
class EncryptionStream(
    private var outermostStream: OutputStream,
    private val options: ProducerOptions,
    private val api: PGPainless
) : OutputStream() {

    private val resultBuilder: EncryptionResult.Builder = EncryptionResult.builder()
    private var closed: Boolean = false

    private var signatureLayerStream: OutputStream? = null
    private var armorOutputStream: ArmoredOutputStream? = null
    private var publicKeyEncryptedStream: OutputStream? = null
    private var compressedDataGenerator: PGPCompressedDataGenerator? = null
    private var basicCompressionStream: BCPGOutputStream? = null
    private var literalDataGenerator: PGPLiteralDataGenerator? = null
    private var literalDataStream: OutputStream? = null

    init {
        prepareArmor()
        prepareEncryption()
        prepareCompression()
        prepareOnePassSignatures()
        prepareLiteralDataProcessing()
        prepareSigningStream()
        prepareInputEncoding()
    }

    private fun prepareArmor() {
        if (!options.isAsciiArmor) {
            return
        }

        outermostStream = BufferedOutputStream(outermostStream)
        armorOutputStream =
            ArmoredOutputStreamFactory.get(outermostStream, options).also { outermostStream = it }
    }

    @Throws(IOException::class, PGPException::class)
    private fun prepareEncryption() {
        if (options.encryptionOptions == null) {
            return
        }
        require(options.encryptionOptions.encryptionMethods.isNotEmpty()) {
            "If EncryptionOptions are provided, at least one encryption method MUST be provided as well."
        }

        val mechanism: MessageEncryptionMechanism =
            options.encryptionOptions.negotiateEncryptionMechanism()
        resultBuilder.setEncryptionMechanism(mechanism)
        val encryptedDataGenerator =
            PGPEncryptedDataGenerator(api.implementation.pgpDataEncryptorBuilder(mechanism))

        options.encryptionOptions.encryptionMethods.forEach { m ->
            encryptedDataGenerator.addMethod(m)
        }
        options.encryptionOptions.encryptionKeyIdentifiers.forEach { r ->
            resultBuilder.addRecipient(r)
        }
        encryptedDataGenerator.setSessionKeyExtractionCallback { pgpSessionKey ->
            if (pgpSessionKey != null) {
                resultBuilder.setSessionKey(SessionKey(pgpSessionKey))
            }
        }

        publicKeyEncryptedStream =
            encryptedDataGenerator.open(outermostStream, ByteArray(BUFFER_SIZE)).also { stream ->
                outermostStream = stream
            }
    }

    @Throws(IOException::class)
    private fun prepareCompression() {
        options.negotiateCompressionAlgorithm(api.algorithmPolicy).let {
            resultBuilder.setCompressionAlgorithm(it)
            compressedDataGenerator = PGPCompressedDataGenerator(it.algorithmId)
            if (it == CompressionAlgorithm.UNCOMPRESSED) return

            basicCompressionStream =
                BCPGOutputStream(compressedDataGenerator!!.open(outermostStream)).also { stream ->
                    outermostStream = stream
                }
        }
    }

    @Throws(IOException::class, PGPException::class)
    private fun prepareOnePassSignatures() {
        signatureLayerStream = outermostStream
        if (options.signingOptions == null) {
            return
        }
        require(options.signingOptions.signingMethods.isNotEmpty()) {
            "If SigningOptions are provided, at least one SigningMethod MUST be provided."
        }
        for ((index, method) in options.signingOptions.signingMethods.values.withIndex()) {
            if (!method.isDetached) {
                // The last sig is not nested, all others are
                val nested = index + 1 < options.signingOptions.signingMethods.size
                method.signatureGenerator.generateOnePassVersion(nested).encode(outermostStream)
            }
        }
    }

    @Throws(IOException::class)
    private fun prepareLiteralDataProcessing() {
        if (options.isCleartextSigned) {
            val hashAlgorithms = collectHashAlgorithmsForCleartextSigning()
            armorOutputStream!!.beginClearText(*hashAlgorithms.toIntArray())
            return
        }

        literalDataGenerator =
            PGPLiteralDataGenerator().also { gen ->
                literalDataStream =
                    gen.open(
                            outermostStream,
                            options.encoding.code,
                            options.fileName,
                            options.modificationDate,
                            ByteArray(BUFFER_SIZE))
                        .also { stream -> outermostStream = stream }
            }
        resultBuilder.apply {
            setFileName(options.fileName)
            setModificationDate(options.modificationDate)
            setFileEncoding(options.encoding)
        }
    }

    private fun prepareSigningStream() {
        outermostStream = SignatureGenerationStream(outermostStream, options.signingOptions)
    }

    private fun prepareInputEncoding() {
        outermostStream =
            CRLFGeneratorStream(
                // By buffering here, we drastically improve performance
                // Reason is that CRLFGeneratorStream only implements write(int), so we need
                // BufferedOutputStream to
                // "convert" to write(buf) calls again
                BufferedOutputStream(outermostStream),
                if (options.isApplyCRLFEncoding) StreamEncoding.UTF8 else StreamEncoding.BINARY)
    }

    private fun collectHashAlgorithmsForCleartextSigning(): Array<Int> {
        return options.signingOptions
            ?.signingMethods
            ?.values
            ?.map { it.hashAlgorithm }
            ?.toSet()
            ?.map { it.algorithmId }
            ?.toTypedArray()
            ?: arrayOf()
    }

    @Throws(IOException::class) override fun write(data: Int) = outermostStream.write(data)

    @Throws(IOException::class)
    override fun write(buffer: ByteArray) = write(buffer, 0, buffer.size)

    @Throws(IOException::class)
    override fun write(buffer: ByteArray, off: Int, len: Int) =
        outermostStream.write(buffer, off, len)

    @Throws(IOException::class) override fun flush() = outermostStream.flush()

    @Throws(IOException::class)
    override fun close() {
        if (closed) return

        outermostStream.close()
        literalDataStream?.apply {
            flush()
            close()
        }
        literalDataGenerator?.close()

        if (options.isCleartextSigned) {
            armorOutputStream?.apply {
                write('\r'.code)
                write('\n'.code)
                endClearText()
            }
        }

        try {
            writeSignatures()
        } catch (e: PGPException) {
            throw IOException("Exception while writing signatures.", e)
        }

        compressedDataGenerator?.close()

        publicKeyEncryptedStream?.apply {
            flush()
            close()
        }

        armorOutputStream?.apply {
            flush()
            close()
        }
        closed = true
    }

    @Throws(PGPException::class, IOException::class)
    private fun writeSignatures() {
        if (options.signingOptions == null) {
            return
        }

        options.signingOptions.signingMethods.entries.reversed().forEach { (key, method) ->
            method.signatureGenerator.generate().let { sig ->
                val documentSignature = OpenPGPDocumentSignature(sig, key)
                if (method.isDetached) {
                    resultBuilder.addDetachedSignature(documentSignature)
                }
                if (!method.isDetached || options.isCleartextSigned) {
                    sig.encode(signatureLayerStream)
                }
            }
        }
    }

    val result: EncryptionResult
        get() =
            check(closed) { "EncryptionStream must be closed before accessing the result." }
                .let { resultBuilder.build() }

    val isClosed
        get() = closed
}
