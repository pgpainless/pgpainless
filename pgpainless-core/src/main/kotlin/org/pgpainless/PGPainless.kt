// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless

import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.util.*
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.BCPGOutputStream
import org.bouncycastle.bcpg.PacketFormat
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
import org.bouncycastle.openpgp.api.OpenPGPSignature
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi
import org.bouncycastle.openpgp.api.bc.BcOpenPGPImplementation
import org.pgpainless.algorithm.OpenPGPKeyVersion
import org.pgpainless.bouncycastle.PolicyAdapter
import org.pgpainless.bouncycastle.extensions.setAlgorithmSuite
import org.pgpainless.decryption_verification.DecryptionBuilder
import org.pgpainless.decryption_verification.DecryptionStream
import org.pgpainless.decryption_verification.MessageMetadata
import org.pgpainless.encryption_signing.EncryptionBuilder
import org.pgpainless.encryption_signing.SignatureReader
import org.pgpainless.key.certification.CertifyCertificate
import org.pgpainless.key.generation.KeyRingBuilder
import org.pgpainless.key.generation.KeyRingTemplates
import org.pgpainless.key.info.KeyRingInfo
import org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditor
import org.pgpainless.policy.Policy
import org.pgpainless.util.ArmorUtils

/**
 * Main entry point to the PGPainless OpenPGP API. Historically, this class was used through static
 * factory methods only, and configuration was done using the Singleton pattern. However, now it is
 * recommended to instantiate the API and apply configuration on a per-instance manner. The benefit
 * of this being that you can have multiple differently configured instances at the same time.
 *
 * @param implementation OpenPGP Implementation - either BCs lightweight
 *   [org.bouncycastle.openpgp.api.bc.BcOpenPGPImplementation] or JCAs
 *   [org.bouncycastle.openpgp.api.jcajce.JcaOpenPGPImplementation].
 * @param algorithmPolicy policy, deciding acceptable algorithms
 */
class PGPainless(
    val implementation: OpenPGPImplementation = createOpenPGPImplementation(),
    val algorithmPolicy: Policy = Policy()
) {

    constructor(algorithmPolicy: Policy) : this(createOpenPGPImplementation(), algorithmPolicy)

    private val api: OpenPGPApi

    init {
        implementation.setPolicy(
            PolicyAdapter(algorithmPolicy)) // adapt PGPainless' Policy to BCs OpenPGPPolicy
        api = BcOpenPGPApi(implementation)
    }

    @JvmOverloads
    fun toAsciiArmor(
        certOrKey: OpenPGPCertificate,
        packetFormat: PacketFormat = PacketFormat.ROUNDTRIP
    ): String {
        val armorBuilder = ArmoredOutputStream.builder().clearHeaders()
        ArmorUtils.keyToHeader(certOrKey.primaryKey.pgpPublicKey)
            .getOrDefault(ArmorUtils.HEADER_COMMENT, setOf())
            .forEach { armorBuilder.addComment(it) }
        return certOrKey.toAsciiArmoredString(packetFormat, armorBuilder)
    }

    @JvmOverloads
    fun toAsciiArmor(
        certsOrKeys: Collection<OpenPGPCertificate>,
        packetFormat: PacketFormat = PacketFormat.ROUNDTRIP
    ): String {
        return certsOrKeys.joinToString(
            separator = "\n", transform = { it.toAsciiArmoredString(packetFormat) })
    }

    @JvmOverloads
    fun toAsciiArmor(
        signature: OpenPGPSignature,
        packetFormat: PacketFormat = PacketFormat.ROUNDTRIP
    ): String {
        val armorBuilder = ArmoredOutputStream.builder().clearHeaders()
        armorBuilder.addComment(signature.keyIdentifier.toPrettyPrint())
        return signature.toAsciiArmoredString(packetFormat, armorBuilder)
    }

    @JvmOverloads
    fun toAsciiArmor(
        signature: PGPSignature,
        packetFormat: PacketFormat = PacketFormat.ROUNDTRIP
    ): String {
        val armorBuilder = ArmoredOutputStream.builder().clearHeaders()
        OpenPGPSignature.getMostExpressiveIdentifier(signature.keyIdentifiers)?.let {
            armorBuilder.addComment(it.toPrettyPrint())
        }
        val bOut = ByteArrayOutputStream()
        val aOut = armorBuilder.build(bOut)
        val pOut = BCPGOutputStream(aOut, packetFormat)
        signature.encode(pOut)
        pOut.close()
        aOut.close()
        return bOut.toString()
    }

    /**
     * Generate a new [OpenPGPKey] from predefined templates.
     *
     * @param version [OpenPGPKeyVersion], defaults to [OpenPGPKeyVersion.v4]
     * @param creationTime of the key, defaults to now
     * @return [KeyRingTemplates] api
     */
    @JvmOverloads
    fun generateKey(
        version: OpenPGPKeyVersion = OpenPGPKeyVersion.v4,
        creationTime: Date = Date()
    ): KeyRingTemplates = KeyRingTemplates(version, creationTime, this)

    /**
     * Build a fresh, custom [OpenPGPKey] using PGPainless' API.
     *
     * @param version [OpenPGPKeyVersion], defaults to [OpenPGPKeyVersion.v4]
     * @return [KeyRingBuilder] api
     */
    @JvmOverloads
    fun buildKey(version: OpenPGPKeyVersion = OpenPGPKeyVersion.v4): KeyRingBuilder =
        KeyRingBuilder(version, this)

    /**
     * Build a fresh, custom [OpenPGPKey] using BCs new API.
     *
     * @param version [OpenPGPKeyVersion], defaults to [OpenPGPKeyVersion.v4]
     * @param creationTime creation time of the key, defaults to now
     * @return [OpenPGPKeyGenerator] api
     */
    @JvmOverloads
    fun _buildKey(
        version: OpenPGPKeyVersion = OpenPGPKeyVersion.v4,
        creationTime: Date = Date()
    ): OpenPGPKeyGenerator =
        OpenPGPKeyGenerator(
                implementation,
                version.numeric,
                algorithmPolicy.keyProtectionSettings.aead,
                creationTime)
            .setAlgorithmSuite(algorithmPolicy.keyGenerationAlgorithmSuite)

    /**
     * Inspect an [OpenPGPKey] or [OpenPGPCertificate], gaining convenient access to its properties.
     *
     * @param keyOrCertificate [OpenPGPKey] or [OpenPGPCertificate]
     * @param referenceTime reference time for evaluation
     * @return [KeyRingInfo] wrapper
     */
    @JvmOverloads
    fun inspect(keyOrCertificate: OpenPGPCertificate, referenceTime: Date = Date()): KeyRingInfo =
        KeyRingInfo(keyOrCertificate, this, referenceTime)

    /**
     * Modify an [OpenPGPKey], adding new components and signatures. This API can be used to add new
     * subkeys, user-ids or user-attributes to the key, extend or alter its expiration time, revoke
     * individual components of the entire certificate, etc.
     *
     * @param key key to modify
     * @param referenceTime timestamp for modifications
     * @return [SecretKeyRingEditor] api
     */
    @JvmOverloads
    fun modify(key: OpenPGPKey, referenceTime: Date = Date()): SecretKeyRingEditor =
        SecretKeyRingEditor(key, this, referenceTime)

    /**
     * Parse [OpenPGPKey]/[OpenPGPCertificate] material from binary or ASCII armored encoding.
     *
     * @return [OpenPGPKeyReader] api
     */
    fun readKey(): OpenPGPKeyReader = api.readKeyOrCertificate()

    /** Parse [PGPSignature] material from binary or ascii armored encoding. */
    fun readSignatures(): SignatureReader = SignatureReader()

    /**
     * Convert a [PGPSecretKeyRing] into an [OpenPGPKey].
     *
     * @param secretKeyRing mid-level API [PGPSecretKeyRing] object
     * @return high-level API [OpenPGPKey] object
     */
    fun toKey(secretKeyRing: PGPSecretKeyRing): OpenPGPKey =
        OpenPGPKey(secretKeyRing, implementation)

    /**
     * Convert a [PGPPublicKeyRing] into an [OpenPGPCertificate].
     *
     * @param certificate mid-level API [PGPSecretKeyRing] object
     * @return high-level API [OpenPGPCertificate] object
     */
    fun toCertificate(certificate: PGPPublicKeyRing): OpenPGPCertificate =
        OpenPGPCertificate(certificate, implementation)

    /**
     * Depending on the type, convert either a [PGPSecretKeyRing] into an [OpenPGPKey] or a
     * [PGPPublicKeyRing] into an [OpenPGPCertificate].
     *
     * @param keyOrCertificate [PGPKeyRing], either [PGPSecretKeyRing] or [PGPPublicKeyRing]
     * @return depending on the type of [keyOrCertificate], either an [OpenPGPKey] or
     *   [OpenPGPCertificate]
     */
    fun toKeyOrCertificate(keyOrCertificate: PGPKeyRing): OpenPGPCertificate =
        when (keyOrCertificate) {
            is PGPSecretKeyRing -> toKey(keyOrCertificate)
            is PGPPublicKeyRing -> toCertificate(keyOrCertificate)
            else ->
                throw IllegalArgumentException(
                    "Unexpected PGPKeyRing subclass: ${keyOrCertificate.javaClass.name}")
        }

    /**
     * Merge two copies of an [OpenPGPCertificate] into a single copy. This method can be used to
     * import new third-party signatures into a certificate.
     *
     * @param originalCopy local copy of the certificate
     * @param updatedCopy copy of the same certificate, potentially carrying new signatures and
     *   components
     * @return merged [OpenPGPCertificate]
     */
    fun mergeCertificate(
        originalCopy: OpenPGPCertificate,
        updatedCopy: OpenPGPCertificate
    ): OpenPGPCertificate {
        return OpenPGPCertificate.join(originalCopy, updatedCopy)
    }

    /**
     * Generate an encrypted and/or signed OpenPGP message.
     *
     * @return [EncryptionBuilder] api
     */
    fun generateMessage(): EncryptionBuilder = EncryptionBuilder(this)

    /**
     * Process an OpenPGP message. This method attempts decryption of encrypted messages and
     * performs signature verification.
     *
     * Note: Message integrity can only be guaranteed after all the plaintext has been read and the
     * [org.pgpainless.decryption_verification.OpenPgpMessageInputStream] has been successfully
     * closed. It is recommended that applications cache unverified data and only emit it to the
     * user after the stream has been closed successfully. See for example [verifyAndOpen].
     *
     * @return [DecryptionBuilder] api
     */
    fun processMessage(): DecryptionBuilder = DecryptionBuilder(this)

    /**
     * Create certification signatures on third-party [OpenPGPCertificates][OpenPGPCertificate].
     *
     * @return [CertifyCertificate] api
     */
    fun generateCertification(): CertifyCertificate = CertifyCertificate(this)

    companion object {

        @Volatile private var instance: PGPainless? = null

        @JvmStatic
        fun getInstance(): PGPainless =
            instance ?: synchronized(this) { instance ?: PGPainless().also { instance = it } }

        @JvmStatic
        fun setInstance(api: PGPainless) {
            instance = api
        }

        @JvmStatic
        fun createOpenPGPImplementation(): OpenPGPImplementation {
            return BcOpenPGPImplementation()
        }

        /**
         * Wrap a key or certificate in ASCII armor.
         *
         * @param key key or certificate
         * @return ascii armored string
         * @throws IOException in case of an error during the armoring process
         */
        @JvmStatic
        fun asciiArmor(key: PGPKeyRing): String =
            getInstance().toAsciiArmor(getInstance().toKeyOrCertificate(key))

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
         * Make changes to a secret key at the given reference time. This method can be used to
         * change key expiration dates and passphrases, or add/revoke user-ids and subkeys.
         *
         * <p>
         * After making the desired changes in the builder, the modified key can be extracted using
         * [org.pgpainless.key.modification.secretkeyring.SecretKeyRingEditorInterface.done].
         *
         * @param secretKey secret key ring
         * @param referenceTime reference time used as signature creation date
         * @return builder
         */
        @JvmStatic
        @JvmOverloads
        @Deprecated(
            "Use .getInstance().modify(key, referenceTime) instead.",
            replaceWith = ReplaceWith("getInstance().modify(key, referenceTime)"))
        fun modifyKeyRing(
            secretKey: PGPSecretKeyRing,
            referenceTime: Date = Date()
        ): SecretKeyRingEditor = getInstance().modify(getInstance().toKey(secretKey), referenceTime)

        /**
         * Utility method for processing smaller OpenPGP messages safely. Process the plaintext data
         * from the given [DecryptionStream], reading it into a local buffer of size
         * [maxPlaintextSize]. If the plaintext data exceeds the buffer, this method throws an
         * [OutOfMemoryError]. After reaching EOF, close the [DecryptionStream], performing
         * integrity verification. Lastly, reopen the local buffer as a new [DecryptionStream] which
         * exposes the verified data along with the finished [MessageMetadata].
         *
         * @param inputStream initial [DecryptionStream]
         * @param maxPlaintextSize maximum plaintext size. 32mb by default.
         * @return verified [DecryptionStream] with finished [MessageMetadata]
         */
        @JvmStatic
        @JvmOverloads
        fun verifyAndOpen(
            inputStream: DecryptionStream,
            maxPlaintextSize: Int = 32 * 1024 * 1024
        ): DecryptionStream {
            val bytes = inputStream.readNBytes(maxPlaintextSize)
            if (inputStream.read() != -1) {
                throw OutOfMemoryError(
                    "Exceeding maximum plaintext size limit of $maxPlaintextSize bytes")
            }
            inputStream.close()
            val verifiedMetadata = inputStream.metadata
            val verifiedIn = bytes.inputStream()

            return object : DecryptionStream() {
                override val metadata: MessageMetadata = verifiedMetadata

                override fun read(): Int = verifiedIn.read()

                override fun read(b: ByteArray): Int = verifiedIn.read(b)

                override fun read(b: ByteArray, off: Int, len: Int): Int =
                    verifiedIn.read(b, off, len)
            }
        }
    }
}
