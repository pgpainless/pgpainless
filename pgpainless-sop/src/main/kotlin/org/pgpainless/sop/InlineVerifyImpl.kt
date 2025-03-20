// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.InputStream
import java.io.OutputStream
import java.util.*
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.util.io.Streams
import org.pgpainless.PGPainless
import org.pgpainless.decryption_verification.ConsumerOptions
import org.pgpainless.exception.MalformedOpenPgpMessageException
import org.pgpainless.exception.MissingDecryptionMethodException
import sop.ReadyWithResult
import sop.Verification
import sop.exception.SOPGPException
import sop.operation.InlineVerify

/** Implementation of the `inline-verify` operation using PGPainless. */
class InlineVerifyImpl(private val api: PGPainless) : InlineVerify {

    private val options = ConsumerOptions.get(api)

    override fun cert(cert: InputStream): InlineVerify = apply {
        options.addVerificationCerts(KeyReader.readPublicKeys(cert, true))
    }

    override fun data(data: InputStream): ReadyWithResult<List<Verification>> {
        return object : ReadyWithResult<List<Verification>>() {
            override fun writeTo(outputStream: OutputStream): List<Verification> {
                try {
                    val verificationStream =
                        PGPainless.decryptAndOrVerify().onInputStream(data).withOptions(options)

                    Streams.pipeAll(verificationStream, outputStream)
                    verificationStream.close()

                    val result = verificationStream.metadata
                    val verifications =
                        if (result.isUsingCleartextSignatureFramework) {
                                result.verifiedDetachedSignatures
                            } else {
                                result.verifiedInlineSignatures
                            }
                            .map { VerificationHelper.mapVerification(it) }

                    if (options.getCertificateSource().getExplicitCertificates().isNotEmpty() &&
                        verifications.isEmpty()) {
                        throw SOPGPException.NoSignature()
                    }

                    return verifications
                } catch (e: MissingDecryptionMethodException) {
                    throw SOPGPException.BadData("Cannot verify encrypted message.", e)
                } catch (e: MalformedOpenPgpMessageException) {
                    throw SOPGPException.BadData(e)
                } catch (e: PGPException) {
                    throw SOPGPException.BadData(e)
                }
            }
        }
    }

    override fun notAfter(timestamp: Date): InlineVerify = apply {
        options.verifyNotAfter(timestamp)
    }

    override fun notBefore(timestamp: Date): InlineVerify = apply {
        options.verifyNotBefore(timestamp)
    }
}
