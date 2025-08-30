// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.InputStream
import java.io.OutputStream
import java.lang.RuntimeException
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.util.io.Streams
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.algorithm.DocumentSignatureType
import org.pgpainless.algorithm.StreamEncoding
import org.pgpainless.encryption_signing.ProducerOptions
import org.pgpainless.encryption_signing.SigningOptions
import org.pgpainless.exception.KeyException.MissingSecretKeyException
import org.pgpainless.exception.KeyException.UnacceptableSigningKeyException
import sop.Ready
import sop.enums.InlineSignAs
import sop.exception.SOPGPException
import sop.operation.InlineSign

/** Implementation of the `inline-sign` operation using PGPainless. */
class InlineSignImpl(private val api: PGPainless) : InlineSign {

    private val signingOptions = SigningOptions.get(api)
    private val protector = MatchMakingSecretKeyRingProtector()
    private val signingKeys = mutableListOf<OpenPGPKey>()

    private var armor = true
    private var mode = InlineSignAs.binary

    override fun data(data: InputStream): Ready {
        signingKeys.forEach { key ->
            try {
                if (mode == InlineSignAs.clearsigned) {
                    signingOptions.addDetachedSignature(protector, key, modeToSigType(mode))
                } else {
                    signingOptions.addInlineSignature(protector, key, modeToSigType(mode))
                }
            } catch (e: UnacceptableSigningKeyException) {
                throw SOPGPException.KeyCannotSign("Key ${key.keyIdentifier} cannot sign.", e)
            } catch (e: MissingSecretKeyException) {
                throw SOPGPException.KeyCannotSign(
                    "Key ${key.keyIdentifier} does not have the secret signing key component available.",
                    e)
            } catch (e: PGPException) {
                throw SOPGPException.KeyIsProtected(
                    "Key ${key.keyIdentifier} cannot be unlocked.", e)
            }
        }

        val producerOptions =
            ProducerOptions.sign(signingOptions).apply {
                when (mode) {
                    InlineSignAs.clearsigned -> {
                        setCleartextSigned()
                        setAsciiArmor(true) // CSF is always armored
                        setEncoding(StreamEncoding.TEXT)
                        applyCRLFEncoding()
                    }
                    InlineSignAs.text -> {
                        setEncoding(StreamEncoding.TEXT)
                        applyCRLFEncoding()
                    }
                    else -> {
                        setAsciiArmor(armor)
                    }
                }
                overrideCompressionAlgorithm(CompressionAlgorithm.UNCOMPRESSED)
            }

        return object : Ready() {
            override fun writeTo(outputStream: OutputStream) {
                try {
                    val signingStream =
                        api.generateMessage()
                            .onOutputStream(outputStream)
                            .withOptions(producerOptions)

                    Streams.pipeAll(data, signingStream)
                    signingStream.close()

                    // forget passphrases
                    protector.clear()
                } catch (e: PGPException) {
                    throw RuntimeException(e)
                }
            }
        }
    }

    override fun key(key: InputStream): InlineSign = apply {
        KeyReader(api).readSecretKeys(key, true).forEach {
            val info = api.inspect(it)
            if (!info.isUsableForSigning) {
                throw SOPGPException.KeyCannotSign(
                    "Key ${info.keyIdentifier} does not have valid, signing capable subkeys.")
            }
            protector.addSecretKey(it)
            signingKeys.add(it)
        }
    }

    override fun mode(mode: InlineSignAs): InlineSign = apply { this.mode = mode }

    override fun noArmor(): InlineSign = apply { armor = false }

    override fun withKeyPassword(password: ByteArray): InlineSign = apply {
        PasswordHelper.addPassphrasePlusRemoveWhitespace(password, protector)
    }

    private fun modeToSigType(mode: InlineSignAs): DocumentSignatureType {
        return when (mode) {
            InlineSignAs.binary -> DocumentSignatureType.BINARY_DOCUMENT
            InlineSignAs.text -> DocumentSignatureType.CANONICAL_TEXT_DOCUMENT
            InlineSignAs.clearsigned -> DocumentSignatureType.CANONICAL_TEXT_DOCUMENT
        }
    }
}
