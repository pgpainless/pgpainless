// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util

import java.io.OutputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.PacketFormat
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.pgpainless.bouncycastle.extensions.asciiArmor
import org.pgpainless.bouncycastle.extensions.encode

class OpenPGPCertificateUtil private constructor() {

    companion object {
        @JvmStatic
        @JvmOverloads
        fun encode(
            certs: Collection<OpenPGPCertificate>,
            outputStream: OutputStream,
            packetFormat: PacketFormat = PacketFormat.ROUNDTRIP
        ) {
            for (cert in certs) {
                cert.encode(outputStream, packetFormat)
            }
        }

        @JvmStatic
        @JvmOverloads
        fun armor(
            certs: Collection<OpenPGPCertificate>,
            outputStream: OutputStream,
            packetFormat: PacketFormat = PacketFormat.ROUNDTRIP
        ) {
            if (certs.size == 1) {
                // Add pretty armor header to single cert/key
                certs.iterator().next().asciiArmor(outputStream, packetFormat)
            } else {
                // Do not add a pretty header
                val aOut = ArmoredOutputStream(outputStream)
                for (cert in certs) {
                    cert.encode(aOut, packetFormat)
                }
                aOut.close()
            }
        }
    }
}
