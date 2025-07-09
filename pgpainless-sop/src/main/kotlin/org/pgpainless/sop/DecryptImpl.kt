// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import org.bouncycastle.bcpg.UnsupportedPacketVersionException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.*
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.util.io.Streams
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.SymmetricKeyAlgorithm
import org.pgpainless.decryption_verification.ConsumerOptions
import org.pgpainless.exception.MalformedOpenPgpMessageException
import org.pgpainless.exception.MissingDecryptionMethodException
import org.pgpainless.exception.ModificationDetectionException
import org.pgpainless.exception.WrongPassphraseException
import sop.DecryptionResult
import sop.ReadyWithResult
import sop.SessionKey
import sop.exception.SOPGPException
import sop.operation.Decrypt
import java.util.zip.ZipException
import kotlin.NoSuchElementException

/** Implementation of the `decrypt` operation using PGPainless. */
class DecryptImpl(private val api: PGPainless) : Decrypt {

    private val consumerOptions = ConsumerOptions.get(api)
    private val protector = MatchMakingSecretKeyRingProtector()

    override fun ciphertext(ciphertext: InputStream): ReadyWithResult<DecryptionResult> {
        if (consumerOptions.getDecryptionKeys().isEmpty() &&
            consumerOptions.getDecryptionPassphrases().isEmpty() &&
            consumerOptions.getSessionKey() == null) {
            throw SOPGPException.MissingArg("Missing decryption key, passphrase or session key.")
        }

        val decryptionStream =
            try {
                api.processMessage().onInputStream(ciphertext).withOptions(consumerOptions)
            } catch (e: MissingDecryptionMethodException) {
                throw SOPGPException.CannotDecrypt(
                    "No usable decryption key or password provided.", e)
            } catch (e: WrongPassphraseException) {
                throw SOPGPException.KeyIsProtected()
            } catch (e: MalformedOpenPgpMessageException) {
                throw SOPGPException.BadData(e)
            } catch (e: PGPException) {
                throw SOPGPException.BadData(e)
            } catch (e: IOException) {
                throw SOPGPException.BadData(e)
            } catch (e: UnsupportedPacketVersionException) {
                throw SOPGPException.BadData(e)
            } catch (e: ModificationDetectionException) {
                throw SOPGPException.BadData(e)
            }
            finally {
                // Forget passphrases after decryption
                protector.clear()
            }

        return object : ReadyWithResult<DecryptionResult>() {
            override fun writeTo(outputStream: OutputStream): DecryptionResult {
                try {
                    Streams.pipeAll(decryptionStream, outputStream)
                    decryptionStream.close()
                } catch (e: MalformedOpenPgpMessageException) {
                    throw SOPGPException.BadData(e)
                } catch (e: ModificationDetectionException) {
                    throw SOPGPException.BadData(e)
                } catch (e: ZipException) {
                    throw SOPGPException.BadData(e)
                } catch (e: IOException) {
                    throw SOPGPException.BadData(e)
                } catch (e: NoSuchElementException) {
                    throw SOPGPException.BadData(e)
                }

                val metadata = decryptionStream.metadata
                if (!metadata.isEncrypted) {
                    throw SOPGPException.BadData("Data is not encrypted.")
                }

                val verificationList =
                    metadata.verifiedInlineSignatures.map { VerificationHelper.mapVerification(it) }

                val sessionKey: SessionKey? =
                    metadata.sessionKey?.let {
                        SessionKey(it.algorithm.algorithmId.toByte(), it.key)
                    }
                return DecryptionResult(sessionKey, verificationList)
            }
        }
    }

    override fun verifyNotAfter(timestamp: Date): Decrypt = apply {
        consumerOptions.verifyNotAfter(timestamp)
    }

    override fun verifyNotBefore(timestamp: Date): Decrypt = apply {
        consumerOptions.verifyNotBefore(timestamp)
    }

    override fun verifyWithCert(cert: InputStream): Decrypt = apply {
        consumerOptions.addVerificationCerts(KeyReader(api).readPublicKeys(cert, true))
    }

    override fun withKey(key: InputStream): Decrypt = apply {
        KeyReader(api).readSecretKeys(key, true).forEach {
            protector.addSecretKey(it)
            consumerOptions.addDecryptionKey(it, protector)
        }
    }

    override fun withKeyPassword(password: ByteArray): Decrypt = apply {
        PasswordHelper.addPassphrasePlusRemoveWhitespace(password, protector)
    }

    override fun withPassword(password: String): Decrypt = apply {
        PasswordHelper.addMessagePassphrasePlusRemoveWhitespace(password, consumerOptions)
    }

    override fun withSessionKey(sessionKey: SessionKey): Decrypt = apply {
        consumerOptions.setSessionKey(mapSessionKey(sessionKey))
    }

    private fun mapSessionKey(sessionKey: SessionKey): org.pgpainless.util.SessionKey =
        org.pgpainless.util.SessionKey(
            SymmetricKeyAlgorithm.requireFromId(sessionKey.algorithm.toInt()), sessionKey.key)
}
