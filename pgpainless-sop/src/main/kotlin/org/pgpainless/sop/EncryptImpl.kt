// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.util.io.Streams
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.DocumentSignatureType
import org.pgpainless.algorithm.StreamEncoding
import org.pgpainless.bouncycastle.extensions.openPgpFingerprint
import org.pgpainless.encryption_signing.EncryptionOptions
import org.pgpainless.encryption_signing.ProducerOptions
import org.pgpainless.encryption_signing.SigningOptions
import org.pgpainless.exception.KeyException.UnacceptableEncryptionKeyException
import org.pgpainless.exception.KeyException.UnacceptableSigningKeyException
import org.pgpainless.exception.WrongPassphraseException
import org.pgpainless.util.Passphrase
import sop.EncryptionResult
import sop.Profile
import sop.ReadyWithResult
import sop.enums.EncryptAs
import sop.exception.SOPGPException
import sop.operation.Encrypt
import sop.util.UTF8Util

/** Implementation of the `encrypt` operation using PGPainless. */
class EncryptImpl : Encrypt {

    companion object {
        @JvmField val RFC4880_PROFILE = Profile("rfc4880", "Follow the packet format of rfc4880")

        @JvmField val SUPPORTED_PROFILES = listOf(RFC4880_PROFILE)
    }

    private val encryptionOptions = EncryptionOptions.get()
    private var signingOptions: SigningOptions? = null
    private val signingKeys = mutableListOf<PGPSecretKeyRing>()
    private val protector = MatchMakingSecretKeyRingProtector()

    private var profile = RFC4880_PROFILE.name
    private var mode = EncryptAs.binary
    private var armor = true

    override fun mode(mode: EncryptAs): Encrypt = apply { this.mode = mode }

    override fun noArmor(): Encrypt = apply { this.armor = false }

    override fun plaintext(plaintext: InputStream): ReadyWithResult<EncryptionResult> {
        if (!encryptionOptions.hasEncryptionMethod()) {
            throw SOPGPException.MissingArg("Missing encryption method.")
        }

        val options =
            if (signingOptions != null) {
                    ProducerOptions.signAndEncrypt(encryptionOptions, signingOptions!!)
                } else {
                    ProducerOptions.encrypt(encryptionOptions)
                }
                .setAsciiArmor(armor)
                .setEncoding(modeToStreamEncoding(mode))

        signingKeys.forEach {
            try {
                signingOptions!!.addInlineSignature(protector, it, modeToSignatureType(mode))
            } catch (e: UnacceptableSigningKeyException) {
                throw SOPGPException.KeyCannotSign("Key ${it.openPgpFingerprint} cannot sign", e)
            } catch (e: WrongPassphraseException) {
                throw SOPGPException.KeyIsProtected("Cannot unlock key ${it.openPgpFingerprint}", e)
            } catch (e: PGPException) {
                throw SOPGPException.BadData(e)
            }
        }

        try {
            return object : ReadyWithResult<EncryptionResult>() {
                override fun writeTo(outputStream: OutputStream): EncryptionResult {
                    val encryptionStream =
                        PGPainless.encryptAndOrSign()
                            .onOutputStream(outputStream)
                            .withOptions(options)
                    Streams.pipeAll(plaintext, encryptionStream)
                    encryptionStream.close()
                    // TODO: Extract and emit session key once BC supports that
                    return EncryptionResult(null)
                }
            }
        } catch (e: PGPException) {
            throw IOException(e)
        }
    }

    override fun profile(profileName: String): Encrypt = apply {
        profile =
            SUPPORTED_PROFILES.find { it.name == profileName }?.name
                ?: throw SOPGPException.UnsupportedProfile("encrypt", profileName)
    }

    override fun signWith(key: InputStream): Encrypt = apply {
        if (signingOptions == null) {
            signingOptions = SigningOptions.get()
        }

        val signingKey =
            KeyReader.readSecretKeys(key, true).singleOrNull()
                ?: throw SOPGPException.BadData(
                    AssertionError(
                        "Exactly one secret key at a time expected. Got zero or multiple instead."))

        val info = PGPainless.inspectKeyRing(signingKey)
        if (info.signingSubkeys.isEmpty()) {
            throw SOPGPException.KeyCannotSign("Key ${info.fingerprint} cannot sign.")
        }

        protector.addSecretKey(signingKey)
        signingKeys.add(signingKey)
    }

    override fun withCert(cert: InputStream): Encrypt = apply {
        try {
            encryptionOptions.addRecipients(KeyReader.readPublicKeys(cert, true))
        } catch (e: UnacceptableEncryptionKeyException) {
            throw SOPGPException.CertCannotEncrypt(e.message ?: "Cert cannot encrypt", e)
        } catch (e: IOException) {
            throw SOPGPException.BadData(e)
        }
    }

    override fun withKeyPassword(password: ByteArray): Encrypt = apply {
        protector.addPassphrase(Passphrase.fromPassword(String(password, UTF8Util.UTF8)))
    }

    override fun withPassword(password: String): Encrypt = apply {
        encryptionOptions.addMessagePassphrase(Passphrase.fromPassword(password))
    }

    private fun modeToStreamEncoding(mode: EncryptAs): StreamEncoding {
        return when (mode) {
            EncryptAs.binary -> StreamEncoding.BINARY
            EncryptAs.text -> StreamEncoding.UTF8
        }
    }

    private fun modeToSignatureType(mode: EncryptAs): DocumentSignatureType {
        return when (mode) {
            EncryptAs.binary -> DocumentSignatureType.BINARY_DOCUMENT
            EncryptAs.text -> DocumentSignatureType.CANONICAL_TEXT_DOCUMENT
        }
    }
}
