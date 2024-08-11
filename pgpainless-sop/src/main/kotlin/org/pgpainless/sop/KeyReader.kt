// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.IOException
import java.io.InputStream
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPRuntimeOperationException
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection
import org.pgpainless.PGPainless
import sop.exception.SOPGPException

/** Reader for OpenPGP keys and certificates with error matching according to the SOP spec. */
class KeyReader {

    companion object {
        @JvmStatic
        fun readSecretKeys(
            keyInputStream: InputStream,
            requireContent: Boolean
        ): PGPSecretKeyRingCollection {
            val keys =
                try {
                    PGPainless.readKeyRing().secretKeyRingCollection(keyInputStream)
                } catch (e: IOException) {
                    if (e.message == null) {
                        throw e
                    }
                    if (e.message!!.startsWith("unknown object in stream:") ||
                        e.message!!.startsWith("invalid header encountered")) {
                        throw SOPGPException.BadData(e)
                    }
                    throw e
                }
            if (requireContent && keys.none()) {
                throw SOPGPException.BadData(PGPException("No key data found."))
            }

            return keys
        }

        @JvmStatic
        fun readPublicKeys(
            certIn: InputStream,
            requireContent: Boolean
        ): PGPPublicKeyRingCollection {
            val certs =
                try {
                    PGPainless.readKeyRing().keyRingCollection(certIn, true)
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

            if (certs.pgpSecretKeyRingCollection.any()) {
                throw SOPGPException.BadData(
                    "Secret key components encountered, while certificates were expected.")
            }

            if (requireContent && certs.pgpPublicKeyRingCollection.none()) {
                throw SOPGPException.BadData(PGPException("No cert data found."))
            }
            return certs.pgpPublicKeyRingCollection
        }
    }
}
