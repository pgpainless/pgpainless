// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.InputStream
import java.io.OutputStream
import org.bouncycastle.bcpg.PacketFormat
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.pgpainless.PGPainless
import org.pgpainless.exception.KeyException.UnboundUserIdException
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.util.ArmoredOutputStreamFactory
import org.pgpainless.util.Passphrase
import sop.Ready
import sop.operation.CertifyUserId

class CertifyUserIdImpl(private val api: PGPainless) : CertifyUserId {

    private var armor: Boolean = true
    private val keys: MutableList<OpenPGPKey> = mutableListOf()
    private var requireSelfSig = true
    private val userIds: MutableSet<String> = mutableSetOf()
    private var protector: MatchMakingSecretKeyRingProtector = MatchMakingSecretKeyRingProtector()

    override fun certs(certs: InputStream): Ready {
        return object : Ready() {
            override fun writeTo(outputStream: OutputStream) {
                val out =
                    if (armor) {
                        ArmoredOutputStreamFactory.get(outputStream)
                    } else outputStream

                api.readKey()
                    .parseCertificates(certs)
                    .onEach { cert ->
                        if (requireSelfSig) {
                            // Check for non-bound user-ids
                            userIds
                                .find { cert.getUserId(it)?.isBound != true }
                                ?.let {
                                    throw UnboundUserIdException(
                                        OpenPgpFingerprint.Companion.of(cert), it, null, null)
                                }
                        }
                    }
                    .forEach { cert ->
                        var certificate = cert
                        keys.forEach { key ->
                            userIds.forEach { userId ->
                                certificate =
                                    api.generateCertification()
                                        .certifyUserId(userId, certificate)
                                        .withKey(key, protector)
                                        .build()
                                        .certifiedCertificate
                            }
                        }

                        out.write(certificate.getEncoded(PacketFormat.CURRENT))
                    }

                out.close()
                if (armor) {
                    // armored output stream does not close inner stream
                    outputStream.close()
                }
            }
        }
    }

    override fun keys(keys: InputStream): CertifyUserId = apply {
        this.keys.addAll(api.readKey().parseKeys(keys).onEach { protector.addSecretKey(it) })
    }

    override fun noArmor(): CertifyUserId = apply { armor = false }

    override fun noRequireSelfSig(): CertifyUserId = apply { requireSelfSig = false }

    override fun userId(userId: String): CertifyUserId = apply { this.userIds.add(userId) }

    override fun withKeyPassword(password: ByteArray): CertifyUserId = apply {
        protector.addPassphrase(Passphrase.fromPassword(String(password)))
    }
}
