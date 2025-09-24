// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.InputStream
import java.io.OutputStream
import org.pgpainless.PGPainless
import org.pgpainless.util.OpenPGPCertificateUtil
import sop.Ready
import sop.operation.ExtractCert

/** Implementation of the `extract-cert` operation using PGPainless. */
class ExtractCertImpl(private val api: PGPainless) : ExtractCert {

    private var armor = true

    override fun key(keyInputStream: InputStream): Ready {
        val certs = KeyReader(api).readSecretKeys(keyInputStream, true).map { it.toCertificate() }

        return object : Ready() {
            override fun writeTo(outputStream: OutputStream) {
                if (armor) {
                    OpenPGPCertificateUtil.armor(certs, outputStream)
                } else {
                    OpenPGPCertificateUtil.encode(certs, outputStream)
                }
            }
        }
    }

    override fun noArmor(): ExtractCert = apply { armor = false }
}
