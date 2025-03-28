// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.InputStream
import java.io.OutputStream
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.util.io.Streams
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.algorithm.DocumentSignatureType
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.encryption_signing.ProducerOptions
import org.pgpainless.encryption_signing.SigningOptions
import org.pgpainless.exception.KeyException.MissingSecretKeyException
import org.pgpainless.exception.KeyException.UnacceptableSigningKeyException
import org.pgpainless.util.ArmoredOutputStreamFactory
import org.pgpainless.util.Passphrase
import sop.MicAlg
import sop.ReadyWithResult
import sop.SigningResult
import sop.enums.SignAs
import sop.exception.SOPGPException
import sop.operation.DetachedSign
import sop.util.UTF8Util

/** Implementation of the `sign` operation using PGPainless. */
class DetachedSignImpl(private val api: PGPainless) : DetachedSign {

    private val signingOptions = SigningOptions.get(api)
    private val protector = MatchMakingSecretKeyRingProtector()
    private val signingKeys = mutableListOf<OpenPGPKey>()

    private var armor = true
    private var mode = SignAs.binary

    override fun data(data: InputStream): ReadyWithResult<SigningResult> {
        signingKeys.forEach {
            try {
                signingOptions.addDetachedSignature(protector, it, modeToSigType(mode))
            } catch (e: UnacceptableSigningKeyException) {
                throw SOPGPException.KeyCannotSign("Key ${it.keyIdentifier} cannot sign.", e)
            } catch (e: MissingSecretKeyException) {
                throw SOPGPException.KeyCannotSign(
                    "Key ${it.keyIdentifier} cannot sign. Missing secret key.", e)
            } catch (e: PGPException) {
                throw SOPGPException.KeyIsProtected(
                    "Key ${it.keyIdentifier} cannot be unlocked.", e)
            }
        }

        try {
            val signingStream =
                api.generateMessage()
                    .discardOutput()
                    .withOptions(
                        ProducerOptions.sign(signingOptions, api)
                            .setAsciiArmor(armor)
                            .overrideCompressionAlgorithm(CompressionAlgorithm.UNCOMPRESSED))

            return object : ReadyWithResult<SigningResult>() {
                override fun writeTo(outputStream: OutputStream): SigningResult {
                    check(!signingStream.isClosed) { "The operation is a one-shot object." }

                    Streams.pipeAll(data, signingStream)
                    signingStream.close()
                    val result = signingStream.result

                    // forget passphrases
                    protector.clear()

                    val signatures = result.detachedSignatures.map { it.value }.flatten()
                    val out =
                        if (armor) ArmoredOutputStreamFactory.get(outputStream) else outputStream

                    signatures.forEach { it.encode(out) }
                    out.close()
                    outputStream.close()

                    return SigningResult.builder()
                        .setMicAlg(micAlgFromSignatures(signatures))
                        .build()
                }
            }
        } catch (e: PGPException) {
            throw RuntimeException(e)
        }
    }

    override fun key(key: InputStream): DetachedSign = apply {
        KeyReader(api).readSecretKeys(key, true).forEach {
            val info = api.inspect(it)
            if (!info.isUsableForSigning) {
                throw SOPGPException.KeyCannotSign(
                    "Key ${info.fingerprint} does not have valid, signing capable subkeys.")
            }
            protector.addSecretKey(it)
            signingKeys.add(it)
        }
    }

    override fun mode(mode: SignAs): DetachedSign = apply { this.mode = mode }

    override fun noArmor(): DetachedSign = apply { armor = false }

    override fun withKeyPassword(password: ByteArray): DetachedSign = apply {
        protector.addPassphrase(Passphrase.fromPassword(String(password, UTF8Util.UTF8)))
    }

    private fun modeToSigType(mode: SignAs): DocumentSignatureType {
        return when (mode) {
            SignAs.binary -> DocumentSignatureType.BINARY_DOCUMENT
            SignAs.text -> DocumentSignatureType.CANONICAL_TEXT_DOCUMENT
        }
    }

    private fun micAlgFromSignatures(signatures: List<PGPSignature>): MicAlg =
        signatures
            .mapNotNull { HashAlgorithm.fromId(it.hashAlgorithm) }
            .toSet()
            .singleOrNull()
            ?.let { MicAlg.fromHashAlgorithmId(it.algorithmId) }
            ?: MicAlg.empty()
}
