// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.lang.RuntimeException
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.pgpainless.PGPainless
import org.pgpainless.bouncycastle.extensions.openPgpFingerprint
import org.pgpainless.exception.WrongPassphraseException
import org.pgpainless.key.util.KeyRingUtils
import org.pgpainless.key.util.RevocationAttributes
import org.pgpainless.util.ArmoredOutputStreamFactory
import sop.Ready
import sop.exception.SOPGPException
import sop.operation.RevokeKey

class RevokeKeyImpl : RevokeKey {

    private val protector = MatchMakingSecretKeyRingProtector()
    private var armor = true

    override fun keys(keys: InputStream): Ready {
        val secretKeyRings =
            try {
                KeyReader.readSecretKeys(keys, true)
            } catch (e: IOException) {
                throw SOPGPException.BadData("Cannot decode secret keys.", e)
            }

        secretKeyRings.forEach { protector.addSecretKey(it) }

        val revocationCertificates = mutableListOf<PGPPublicKeyRing>()
        secretKeyRings.forEach { secretKeys ->
            val editor = PGPainless.modifyKeyRing(secretKeys)
            try {
                val attributes =
                    RevocationAttributes.createKeyRevocation()
                        .withReason(RevocationAttributes.Reason.NO_REASON)
                        .withoutDescription()
                if (secretKeys.publicKey.version == 6) {
                    revocationCertificates.add(
                        editor.createMinimalRevocationCertificate(protector, attributes))
                } else {
                    val certificate = PGPainless.extractCertificate(secretKeys)
                    val revocation = editor.createRevocation(protector, attributes)
                    revocationCertificates.add(
                        KeyRingUtils.injectCertification(certificate, revocation))
                }
            } catch (e: WrongPassphraseException) {
                throw SOPGPException.KeyIsProtected(
                    "Missing or wrong passphrase for key ${secretKeys.openPgpFingerprint}", e)
            } catch (e: PGPException) {
                throw RuntimeException(
                    "Cannot generate revocation certificate for key ${secretKeys.openPgpFingerprint}",
                    e)
            }
        }

        return object : Ready() {
            override fun writeTo(outputStream: OutputStream) {
                val collection = PGPPublicKeyRingCollection(revocationCertificates)
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
        PasswordHelper.addPassphrasePlusRemoveWhitespace(password, protector)
    }
}
