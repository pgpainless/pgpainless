// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.IOException
import java.io.InputStream
import java.util.*
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.util.io.Streams
import org.pgpainless.PGPainless
import org.pgpainless.decryption_verification.ConsumerOptions
import org.pgpainless.exception.MalformedOpenPgpMessageException
import sop.Verification
import sop.exception.SOPGPException
import sop.operation.DetachedVerify
import sop.operation.VerifySignatures

/** Implementation of the `verify` operation using PGPainless. */
class DetachedVerifyImpl : DetachedVerify {

    private val options = ConsumerOptions.get().forceNonOpenPgpData()

    override fun cert(cert: InputStream): DetachedVerify = apply {
        options.addVerificationCerts(KeyReader.readPublicKeys(cert, true))
    }

    override fun data(data: InputStream): List<Verification> {
        try {
            val verificationStream =
                PGPainless.decryptAndOrVerify().onInputStream(data).withOptions(options)

            Streams.drain(verificationStream)
            verificationStream.close()

            val result = verificationStream.metadata
            val verifications =
                result.verifiedDetachedSignatures.map { VerificationHelper.mapVerification(it) }

            if (options.getCertificateSource().getExplicitCertificates().isNotEmpty() &&
                verifications.isEmpty()) {
                throw SOPGPException.NoSignature()
            }

            return verifications
        } catch (e: MalformedOpenPgpMessageException) {
            throw SOPGPException.BadData(e)
        } catch (e: PGPException) {
            throw SOPGPException.BadData(e)
        }
    }

    override fun notAfter(timestamp: Date): DetachedVerify = apply {
        options.verifyNotAfter(timestamp)
    }

    override fun notBefore(timestamp: Date): DetachedVerify = apply {
        options.verifyNotBefore(timestamp)
    }

    override fun signatures(signatures: InputStream): VerifySignatures = apply {
        try {
            options.addVerificationOfDetachedSignatures(signatures)
        } catch (e: IOException) {
            throw SOPGPException.BadData(e)
        } catch (e: PGPException) {
            throw SOPGPException.BadData(e)
        }
    }
}
