// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import org.bouncycastle.openpgp.PGPException
import org.pgpainless.PGPainless
import org.pgpainless.exception.MissingPassphraseException
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.key.util.KeyRingUtils
import org.pgpainless.util.OpenPGPCertificateUtil
import org.pgpainless.util.Passphrase
import sop.Ready
import sop.exception.SOPGPException
import sop.operation.ChangeKeyPassword

/** Implementation of the `change-key-password` operation using PGPainless. */
class ChangeKeyPasswordImpl(private val api: PGPainless) : ChangeKeyPassword {

    private val oldProtector = MatchMakingSecretKeyRingProtector()
    private var newPassphrase = Passphrase.emptyPassphrase()
    private var armor = true

    override fun keys(keys: InputStream): Ready {
        val newProtector = SecretKeyRingProtector.unlockAnyKeyWith(newPassphrase)
        val secretKeys =
            try {
                KeyReader(api).readSecretKeys(keys, true)
            } catch (e: IOException) {
                throw SOPGPException.BadData(e)
            }

        val updatedSecretKeys =
            secretKeys
                .map {
                    oldProtector.addSecretKey(it)
                    try {
                        return@map KeyRingUtils.changePassphrase(
                            null, it.pgpSecretKeyRing, oldProtector, newProtector)
                    } catch (e: MissingPassphraseException) {
                        throw SOPGPException.KeyIsProtected(
                            "Cannot unlock key ${it.keyIdentifier}", e)
                    } catch (e: PGPException) {
                        if (e.message?.contains("Exception decrypting key") == true) {
                            throw SOPGPException.KeyIsProtected(
                                "Cannot unlock key ${it.keyIdentifier}", e)
                        }
                        throw RuntimeException(
                            "Cannot change passphrase of key ${it.keyIdentifier}", e)
                    }
                }
                .map { api.toKey(it) }

        return object : Ready() {
            override fun writeTo(outputStream: OutputStream) {
                if (armor) {
                    OpenPGPCertificateUtil.armor(updatedSecretKeys, outputStream)
                } else {
                    OpenPGPCertificateUtil.encode(updatedSecretKeys, outputStream)
                }
            }
        }
    }

    override fun newKeyPassphrase(newPassphrase: String): ChangeKeyPassword = apply {
        this.newPassphrase = Passphrase.fromPassword(newPassphrase)
    }

    override fun noArmor(): ChangeKeyPassword = apply { armor = false }

    override fun oldKeyPassphrase(oldPassphrase: String): ChangeKeyPassword = apply {
        oldProtector.addPassphrase(Passphrase.fromPassword(oldPassphrase))
    }
}
