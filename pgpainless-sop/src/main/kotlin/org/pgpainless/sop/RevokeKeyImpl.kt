// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.lang.RuntimeException
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.pgpainless.PGPainless
import org.pgpainless.bouncycastle.extensions.toOpenPGPCertificate
import org.pgpainless.exception.WrongPassphraseException
import org.pgpainless.key.util.KeyRingUtils
import org.pgpainless.key.util.RevocationAttributes
import org.pgpainless.util.ArmoredOutputStreamFactory
import org.pgpainless.util.Passphrase
import sop.Ready
import sop.exception.SOPGPException
import sop.operation.RevokeKey
import sop.util.UTF8Util

class RevokeKeyImpl(private val api: PGPainless) : RevokeKey {

    private val protector = MatchMakingSecretKeyRingProtector()
    private var armor = true

    override fun keys(keys: InputStream): Ready {
        val secretKeys =
            try {
                KeyReader(api).readSecretKeys(keys, true)
            } catch (e: IOException) {
                throw SOPGPException.BadData("Cannot decode secret keys.", e)
            }

        secretKeys.forEach { protector.addSecretKey(it) }

        val revocationCertificates = mutableListOf<OpenPGPCertificate>()
        secretKeys.forEach {
            val editor = api.modify(it)
            try {
                val attributes =
                    RevocationAttributes.createKeyRevocation()
                        .withReason(RevocationAttributes.Reason.NO_REASON)
                        .withoutDescription()
                if (it.primaryKey.version == 6) {
                    revocationCertificates.add(
                        editor.createMinimalRevocationCertificate(protector, attributes))
                } else {
                    val certificate = it.toCertificate()
                    val revocation = editor.createRevocation(protector, attributes)
                    revocationCertificates.add(
                        KeyRingUtils.injectCertification(
                                certificate.pgpKeyRing, revocation.signature)
                            .toOpenPGPCertificate(api.implementation))
                }
            } catch (e: WrongPassphraseException) {
                throw SOPGPException.KeyIsProtected(
                    "Missing or wrong passphrase for key ${it.keyIdentifier}", e)
            } catch (e: PGPException) {
                throw RuntimeException(
                    "Cannot generate revocation certificate for key ${it.keyIdentifier}", e)
            }
        }

        return object : Ready() {
            override fun writeTo(outputStream: OutputStream) {
                val collection =
                    PGPPublicKeyRingCollection(revocationCertificates.map { it.pgpPublicKeyRing })
                if (armor) {
                    val armorOut = ArmoredOutputStreamFactory.get(outputStream)
                    collection.encode(armorOut)
                    armorOut.close()
                } else {
                    collection.encode(outputStream)
                }
            }
        }
    }

    override fun noArmor(): RevokeKey = apply { armor = false }

    override fun withKeyPassword(password: ByteArray): RevokeKey = apply {
        val string =
            try {
                UTF8Util.decodeUTF8(password)
            } catch (e: CharacterCodingException) {
                // TODO: Add cause
                throw SOPGPException.PasswordNotHumanReadable(
                    "Cannot UTF8-decode password: ${e.stackTraceToString()}")
            }
        protector.addPassphrase(Passphrase.fromPassword(string))
    }
}
