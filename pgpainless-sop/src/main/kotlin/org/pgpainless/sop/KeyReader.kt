// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.IOException
import java.io.InputStream
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPRuntimeOperationException
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.pgpainless.PGPainless
import sop.exception.SOPGPException

/** Reader for OpenPGP keys and certificates with error matching according to the SOP spec. */
class KeyReader(val api: PGPainless = PGPainless.getInstance()) {

    fun readSecretKeys(keyInputStream: InputStream, requireContent: Boolean): List<OpenPGPKey> {
        val keys =
            try {
                api.readKey().parseKeys(keyInputStream)
            } catch (e: IOException) {
                if (e.message == null) {
                    throw e
                }
                if (e.message!!.startsWith("unknown object in stream:") ||
                    e.message!!.startsWith("invalid header encountered") ||
                    e.message!!.startsWith("Encountered unexpected packet:")) {
                    throw SOPGPException.BadData(e)
                }
                throw e
            }
        if (requireContent && keys.none()) {
            throw SOPGPException.BadData(PGPException("No key data found."))
        }

        return keys
    }

    fun readPublicKeys(certIn: InputStream, requireContent: Boolean): List<OpenPGPCertificate> {
        val certs =
            try {
                api.readKey().parseKeysOrCertificates(certIn)
            } catch (e: IOException) {
                if (e.message == null) {
                    throw e
                }
                if (e.message!!.startsWith("unknown object in stream:") ||
                    e.message!!.startsWith("invalid header encountered")) {
                    throw SOPGPException.BadData(e)
                }
                throw e
            } catch (e: PGPRuntimeOperationException) {
                throw SOPGPException.BadData(e)
            }

        if (certs.any { it.isSecretKey }) {
            throw SOPGPException.BadData(
                "Secret key components encountered, while certificates were expected.")
        }

        if (requireContent && certs.isEmpty()) {
            throw SOPGPException.BadData("No certificate data found.")
        }

        return certs
    }
}
