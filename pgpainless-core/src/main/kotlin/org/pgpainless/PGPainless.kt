// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless

import java.io.OutputStream
import java.util.*
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.api.OpenPGPApi
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPImplementation
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.api.OpenPGPKeyGenerator
import org.bouncycastle.openpgp.api.OpenPGPKeyReader
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi
import org.pgpainless.algorithm.OpenPGPKeyVersion
import org.pgpainless.bouncycastle.PolicyAdapter
import org.pgpainless.bouncycastle.extensions.setAlgorithmSuite
import org.pgpainless.decryption_verification.DecryptionBuilder
import org.pgpainless.encryption_signing.EncryptionBuilder
import org.pgpainless.key.certification.CertifyCertificate
import org.pgpainless.key.generation.KeyRingBuilder
import org.pgpainless.key.generation.KeyRingTemplates
import org.pgpainless.key.info.KeyRingInfo
import org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditor
import org.pgpainless.key.parsing.KeyRingReader
import org.pgpainless.key.util.KeyRingUtils
import org.pgpainless.policy.Policy
import org.pgpainless.util.ArmorUtils

class PGPainless(
    val implementation: OpenPGPImplementation = OpenPGPImplementation.getInstance(),
    var algorithmPolicy: Policy = Policy.getInstance()
) {

    private var api: OpenPGPApi

    init {
        implementation.setPolicy(
            PolicyAdapter(algorithmPolicy)) // adapt PGPainless' Policy to BCs OpenPGPPolicy
        api = BcOpenPGPApi(implementation)
    }

    @JvmOverloads
    fun generateKey(
        version: OpenPGPKeyVersion = OpenPGPKeyVersion.v4,
        creationTime: Date = Date()
    ): KeyRingTemplates = KeyRingTemplates(version, creationTime, this)

    @JvmOverloads
    fun buildKey(
        version: OpenPGPKeyVersion = OpenPGPKeyVersion.v4,
        creationTime: Date = Date()
    ): OpenPGPKeyGenerator =
        OpenPGPKeyGenerator(
                implementation, version.numeric, version == OpenPGPKeyVersion.v6, creationTime)
            .setAlgorithmSuite(algorithmPolicy.keyGenerationAlgorithmSuite)

    fun readKey(): OpenPGPKeyReader = api.readKeyOrCertificate()

    fun toKey(secretKeyRing: PGPSecretKeyRing): OpenPGPKey =
        OpenPGPKey(secretKeyRing, implementation)

    fun toCertificate(publicKeyRing: PGPPublicKeyRing): OpenPGPCertificate =
        OpenPGPCertificate(publicKeyRing, implementation)

    fun mergeCertificate(
        originalCopy: OpenPGPCertificate,
        updatedCopy: OpenPGPCertificate
    ): OpenPGPCertificate {
        return OpenPGPCertificate.join(originalCopy, updatedCopy)
    }

    /** Generate an encrypted and/or signed OpenPGP message. */
    fun generateMessage(): EncryptionBuilder = EncryptionBuilder(this)

    /**
     * Create certification signatures on third-party [OpenPGPCertificates][OpenPGPCertificate].
     *
     * @return builder
     */
    fun generateCertification(): CertifyCertificate = CertifyCertificate(this)

    companion object {

        @Volatile private var instance: PGPainless? = null

        @JvmStatic
        fun getInstance(): PGPainless =
            instance ?: synchronized(this) { instance ?: PGPainless().also { instance = it } }

        @JvmStatic
        fun setInstance(pgpainless: PGPainless) {
            instance = pgpainless
        }

        /**
         * Generate a fresh [OpenPGPKey] from predefined templates.
         *
         * @return templates
         */
        @JvmStatic
        @JvmOverloads
        @Deprecated(
            "Call .generateKey() on an instance of PGPainless instead.",
            replaceWith = ReplaceWith("generateKey(version)"))
        fun generateKeyRing(version: OpenPGPKeyVersion = OpenPGPKeyVersion.v4): KeyRingTemplates =
            getInstance().generateKey(version)

        /**
         * Build a custom OpenPGP key ring.
         *
         * @return builder
         */
        @JvmStatic
        @JvmOverloads
        fun buildKeyRing(
            version: OpenPGPKeyVersion = OpenPGPKeyVersion.v4,
            api: PGPainless = getInstance()
        ): KeyRingBuilder = KeyRingBuilder(version, api)

        /**
         * Read an existing OpenPGP key ring.
         *
         * @return builder
         */
        @Deprecated("Use readKey() instead.", replaceWith = ReplaceWith("readKey()"))
        @JvmStatic
        fun readKeyRing(): KeyRingReader = KeyRingReader()

        /**
         * Extract a public key certificate from a secret key.
         *
         * @param secretKey secret key
         * @return public key certificate
         */
        @JvmStatic
        @Deprecated("Use .toKey() and then .toCertificate() instead.")
        fun extractCertificate(secretKey: PGPSecretKeyRing): PGPPublicKeyRing =
            KeyRingUtils.publicKeyRingFrom(secretKey)

        /**
         * Merge two copies of the same certificate (e.g. an old copy, and one retrieved from a key
         * server) together.
         *
         * @param originalCopy local, older copy of the cert
         * @param updatedCopy updated, newer copy of the cert
         * @return merged certificate
         * @throws PGPException in case of an error
         */
        @JvmStatic
        @Deprecated("Use mergeCertificate() instead.")
        fun mergeCertificate(
            originalCopy: PGPPublicKeyRing,
            updatedCopy: PGPPublicKeyRing
        ): PGPPublicKeyRing = PGPPublicKeyRing.join(originalCopy, updatedCopy)

        /**
         * Wrap a key or certificate in ASCII armor.
         *
         * @param key key or certificate
         * @return ascii armored string
         * @throws IOException in case of an error during the armoring process
         */
        @JvmStatic
        fun asciiArmor(key: PGPKeyRing): String =
            if (key is PGPSecretKeyRing) ArmorUtils.toAsciiArmoredString(key)
            else ArmorUtils.toAsciiArmoredString(key as PGPPublicKeyRing)

        @JvmStatic fun asciiArmor(cert: OpenPGPCertificate) = asciiArmor(cert.pgpKeyRing)

        /**
         * Wrap a key of certificate in ASCII armor and write the result into the given
         * [OutputStream].
         *
         * @param key key or certificate
         * @param outputStream output stream
         * @throws IOException in case of an error during the armoring process
         */
        @JvmStatic
        fun asciiArmor(key: PGPKeyRing, outputStream: OutputStream) {
            val armorOut = ArmorUtils.toAsciiArmoredStream(key, outputStream)
            key.encode(armorOut)
            armorOut.close()
        }

        /**
         * Wrap the detached signature in ASCII armor.
         *
         * @param signature detached signature
         * @return ascii armored string
         * @throws IOException in case of an error during the armoring process
         */
        @JvmStatic
        @Deprecated("Covert to OpenPGPSignature and call .toAsciiArmoredString() instead.")
        fun asciiArmor(signature: PGPSignature): String = ArmorUtils.toAsciiArmoredString(signature)

        /**
         * Create an [EncryptionBuilder], which can be used to encrypt and/or sign data using
         * OpenPGP.
         *
         * @return builder
         */
        @Deprecated(
            "Call generateMessage() on an instance of PGPainless instead.",
            replaceWith = ReplaceWith("generateMessage()"))
        @JvmStatic
        fun encryptAndOrSign(): EncryptionBuilder = getInstance().generateMessage()

        /**
         * Create a [DecryptionBuilder], which can be used to decrypt and/or verify data using
         * OpenPGP.
         *
         * @return builder
         */
        @JvmStatic fun decryptAndOrVerify(): DecryptionBuilder = DecryptionBuilder()

        /**
         * Make changes to a secret key at the given reference time. This method can be used to
         * change key expiration dates and passphrases, or add/revoke user-ids and subkeys.
         *
         * <p>
         * After making the desired changes in the builder, the modified key can be extracted using
         * [org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditorInterface.done].
         *
         * @param secretKeys secret key ring
         * @param referenceTime reference time used as signature creation date
         * @return builder
         */
        @JvmStatic
        @JvmOverloads
        fun modifyKeyRing(
            secretKey: PGPSecretKeyRing,
            referenceTime: Date = Date(),
            api: PGPainless = getInstance()
        ): SecretKeyRingEditor = SecretKeyRingEditor(secretKey, api, referenceTime)

        /**
         * Quickly access information about a [org.bouncycastle.openpgp.PGPPublicKeyRing] /
         * [PGPSecretKeyRing]. This method can be used to determine expiration dates, key flags and
         * other information about a key at a specific time.
         *
         * @param keyRing key ring
         * @param referenceTime date of inspection
         * @return access object
         */
        @JvmStatic
        @JvmOverloads
        fun inspectKeyRing(key: PGPKeyRing, referenceTime: Date = Date()): KeyRingInfo =
            KeyRingInfo(key, referenceTime)

        @JvmStatic
        @JvmOverloads
        fun inspectKeyRing(key: OpenPGPCertificate, referenceTime: Date = Date()): KeyRingInfo =
            KeyRingInfo(key, getInstance(), referenceTime)

        /**
         * Access, and make changes to PGPainless policy on acceptable/default algorithms etc.
         *
         * @return policy
         */
        @Deprecated(
            "Use PGPainless.getInstance().getAlgorithmPolicy() instead.",
            replaceWith = ReplaceWith("getInstance().algorithmPolicy"))
        @JvmStatic
        fun getPolicy(): Policy = getInstance().algorithmPolicy

        /**
         * Create different kinds of signatures on other keys.
         *
         * @return builder
         */
        @Deprecated(
            "Call .generateCertification() on an instance of PGPainless instead.",
            replaceWith = ReplaceWith("generateCertification()"))
        @JvmStatic
        fun certify(): CertifyCertificate = getInstance().generateCertification()
    }
}
