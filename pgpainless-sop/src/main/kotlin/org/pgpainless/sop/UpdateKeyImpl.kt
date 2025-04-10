// SPDX-FileCopyrightText: 2025 Paul Schaub <info@pgpainless.org>
//
// SPDX-License-Identifier: CC0-1.0

package org.pgpainless.sop

import java.io.InputStream
import java.io.OutputStream
import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.bcpg.PacketFormat
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.pgpainless.PGPainless
import org.pgpainless.util.ArmoredOutputStreamFactory
import org.pgpainless.util.Passphrase
import sop.Ready
import sop.operation.UpdateKey

class UpdateKeyImpl(private val api: PGPainless) : UpdateKey {

    private var armor = true
    private var addCapabilities = true
    private var signingOnly = false
    private val protector: MatchMakingSecretKeyRingProtector = MatchMakingSecretKeyRingProtector()

    private val mergeCerts: MutableMap<KeyIdentifier, OpenPGPCertificate> = mutableMapOf()

    override fun key(key: InputStream): Ready {
        return object : Ready() {
            override fun writeTo(outputStream: OutputStream) {
                val out =
                    if (armor) {
                        ArmoredOutputStreamFactory.get(outputStream)
                    } else {
                        outputStream
                    }

                val keyList = api.readKey().parseKeys(key)
                for (k in keyList) {
                    val updatedKey: OpenPGPKey =
                        if (mergeCerts[k.keyIdentifier] == null) {
                            k
                        } else {
                            val updatedCert: OpenPGPCertificate =
                                api.mergeCertificate(
                                    k.toCertificate(), mergeCerts[k.keyIdentifier]!!)
                            api.toKey(
                                PGPSecretKeyRing.replacePublicKeys(
                                    k.pgpSecretKeyRing, updatedCert.pgpPublicKeyRing))
                        }
                    out.write(updatedKey.getEncoded(PacketFormat.CURRENT))
                }

                if (armor) {
                    out.close()
                }
                outputStream.close()
            }
        }
    }

    override fun mergeCerts(certs: InputStream): UpdateKey = apply {
        val certList = api.readKey().parseCertificates(certs)
        for (cert in certList) {
            if (mergeCerts[cert.keyIdentifier] == null) {
                mergeCerts[cert.keyIdentifier] = cert
            } else {
                val existing = mergeCerts[cert.keyIdentifier]!!
                mergeCerts[cert.keyIdentifier] = api.mergeCertificate(existing, cert)
            }
        }
    }

    override fun noAddedCapabilities(): UpdateKey = apply { addCapabilities = false }

    override fun noArmor(): UpdateKey = apply { armor = false }

    override fun signingOnly(): UpdateKey = apply { signingOnly = true }

    override fun withKeyPassword(password: ByteArray): UpdateKey = apply {
        protector.addPassphrase(Passphrase.fromPassword(String(password)))
    }
}
