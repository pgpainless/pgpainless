// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.InputStream
import java.io.OutputStream
import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.pgpainless.PGPainless
import org.pgpainless.util.ArmoredOutputStreamFactory
import sop.Ready
import sop.operation.MergeCerts

class MergeCertsImpl(private val api: PGPainless) : MergeCerts {

    private var armor = true
    private val baseCerts: MutableMap<KeyIdentifier, OpenPGPCertificate> = mutableMapOf()
    private val updateCerts: MutableList<OpenPGPCertificate> = mutableListOf()

    // from standard input
    override fun baseCertificates(certs: InputStream): Ready {
        return object : Ready() {
            override fun writeTo(outputStream: OutputStream) {
                val baseCertsList = api.readKey().parseCertificates(certs)

                // Index and merge base certs
                for (cert in baseCertsList) {
                    if (!baseCerts.contains(cert.keyIdentifier)) {
                        baseCerts[cert.keyIdentifier] = cert
                    } else {
                        val baseCert = baseCerts[cert.keyIdentifier]!!
                        baseCerts[cert.keyIdentifier] = api.mergeCertificate(baseCert, cert)
                    }
                }

                // Merge updates with base certs
                for (update in updateCerts) {
                    if (baseCerts[update.keyIdentifier] == null) {
                        // skip updates with missing base certs
                        continue
                    }

                    val baseCert = baseCerts[update.keyIdentifier]!!
                    baseCerts[update.keyIdentifier] = api.mergeCertificate(baseCert, update)
                }

                val out =
                    if (armor) {
                        ArmoredOutputStreamFactory.get(outputStream)
                    } else {
                        outputStream
                    }

                // emit merged and updated base certs
                for (merged in baseCerts.values) {
                    out.write(merged.getEncoded())
                }

                if (armor) {
                    out.close()
                }
                outputStream.close()
            }
        }
    }

    override fun noArmor(): MergeCerts = apply { armor = false }

    // from command line
    override fun updates(updateCerts: InputStream): MergeCerts = apply {
        this.updateCerts.addAll(api.readKey().parseCertificates(updateCerts))
    }
}
