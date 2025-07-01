// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.api.MessageEncryptionMechanism
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.util.io.Streams
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.AEADAlgorithm
import org.pgpainless.algorithm.DocumentSignatureType
import org.pgpainless.algorithm.StreamEncoding
import org.pgpainless.algorithm.SymmetricKeyAlgorithm
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
import sop.SessionKey
import sop.enums.EncryptAs
import sop.exception.SOPGPException
import sop.operation.Encrypt
import sop.util.UTF8Util

/** Implementation of the `encrypt` operation using PGPainless. */
class EncryptImpl(private val api: PGPainless) : Encrypt {

    companion object {
        @JvmField val RFC4880_PROFILE = Profile("rfc4880", "Follow the packet format of rfc4880")
        @JvmField val RFC9580_PROFILE = Profile("rfc9580", "Follow the packet format of rfc9580")

        @JvmField
        val SUPPORTED_PROFILES =
            listOf(
                RFC4880_PROFILE.withAliases("default", "compatibility"),
                RFC9580_PROFILE.withAliases("security", "performance"))
    }

    private val encryptionOptions = EncryptionOptions.get(api)
    private var signingOptions: SigningOptions? = null
    private val signingKeys = mutableListOf<OpenPGPKey>()
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

        if (encryptionOptions.usesOnlyPasswordBasedEncryption() &&
            profile == RFC9580_PROFILE.name) {
            encryptionOptions.overrideEncryptionMechanism(
                MessageEncryptionMechanism.aead(
                    SymmetricKeyAlgorithm.AES_128.algorithmId, AEADAlgorithm.OCB.algorithmId))
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
                throw SOPGPException.KeyCannotSign("Key ${it.keyIdentifier} cannot sign", e)
            } catch (e: WrongPassphraseException) {
                throw SOPGPException.KeyIsProtected("Cannot unlock key ${it.keyIdentifier}", e)
            } catch (e: PGPException) {
                throw SOPGPException.BadData(e)
            }
        }

        try {
            return object : ReadyWithResult<EncryptionResult>() {
                override fun writeTo(outputStream: OutputStream): EncryptionResult {
                    val encryptionStream =
                        api.generateMessage().onOutputStream(outputStream).withOptions(options)
                    Streams.pipeAll(plaintext, encryptionStream)
                    encryptionStream.close()
                    return EncryptionResult(
                        encryptionStream.result.sessionKey?.let {
                            SessionKey(it.algorithm.algorithmId.toByte(), it.key)
                        })
                }
            }
        } catch (e: PGPException) {
            throw IOException(e)
        }
    }

    override fun profile(profileName: String): Encrypt = apply {
        profile =
            SUPPORTED_PROFILES.find { it.name == profileName || it.aliases.contains(profileName) }
                ?.name
                ?: throw SOPGPException.UnsupportedProfile("encrypt", profileName)
    }

    override fun signWith(key: InputStream): Encrypt = apply {
        if (signingOptions == null) {
            signingOptions = SigningOptions.get(api)
        }

        val signingKey =
            KeyReader(api).readSecretKeys(key, true).singleOrNull()
                ?: throw SOPGPException.BadData(
                    AssertionError(
                        "Exactly one secret key at a time expected. Got zero or multiple instead."))

        val info = api.inspect(signingKey)
        if (info.signingSubkeys.isEmpty()) {
            throw SOPGPException.KeyCannotSign("Key ${info.keyIdentifier} cannot sign.")
        }

        protector.addSecretKey(signingKey)
        signingKeys.add(signingKey)
    }

    override fun withCert(cert: InputStream): Encrypt = apply {
        try {
            KeyReader(api).readPublicKeys(cert, true).forEach { encryptionOptions.addRecipient(it) }
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
