// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.InputStream
import java.io.OutputStream
import org.pgpainless.PGPainless
import org.pgpainless.util.ArmorUtils
import org.pgpainless.util.ArmoredOutputStreamFactory
import sop.Ready
import sop.operation.ExtractCert

/** Implementation of the `extract-cert` operation using PGPainless. */
class ExtractCertImpl(private val api: PGPainless) : ExtractCert {

    private var armor = true

    override fun key(keyInputStream: InputStream): Ready {
        val certs =
            KeyReader.readSecretKeys(keyInputStream, true).map { PGPainless.extractCertificate(it) }

        return object : Ready() {
            override fun writeTo(outputStream: OutputStream) {
                if (armor) {
                    if (certs.size == 1) {
                        val cert = certs[0]
                        // This way we have a nice armor header with fingerprint and user-ids
                        val armorOut = ArmorUtils.toAsciiArmoredStream(cert, outputStream)
                        cert.encode(armorOut)
                        armorOut.close()
                    } else {
                        // for multiple certs, add no info headers to the ASCII armor
                        val armorOut = ArmoredOutputStreamFactory.get(outputStream)
                        certs.forEach { it.encode(armorOut) }
                        armorOut.close()
                    }
                } else {
                    certs.forEach { it.encode(outputStream) }
                }
            }
        }
    }

    override fun noArmor(): ExtractCert = apply { armor = false }
}
