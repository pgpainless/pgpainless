// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless

import java.io.ByteArrayOutputStream
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
import org.pgpainless.algorithm.AlgorithmSuite
import org.pgpainless.algorithm.CompressionAlgorithm
import org.pgpainless.algorithm.Feature
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.OpenPGPKeyVersion
import org.pgpainless.algorithm.SymmetricKeyAlgorithm
import org.pgpainless.bouncycastle.PolicyAdapter
import org.pgpainless.bouncycastle.extensions.setAlgorithmSuite
import org.pgpainless.decryption_verification.DecryptionBuilder
import org.pgpainless.encryption_signing.EncryptionBuilder
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
    val implementation: OpenPGPImplementation = OpenPGPImplementation.getInstance(),
    val algorithmPolicy: Policy = Policy()
) {

    constructor(
        algorithmPolicy: Policy
    ) : this(OpenPGPImplementation.getInstance(), algorithmPolicy)

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
     * @param version [OpenPGPKeyVersion]
     * @param creationTime of the key, defaults to now
     * @return [KeyRingTemplates] api
     */
    @JvmOverloads
    fun generateKey(
        version: OpenPGPKeyVersion = algorithmPolicy.keyGenerationAlgorithmSuite.keyVersion,
        creationTime: Date = Date()
    ): KeyRingTemplates = KeyRingTemplates(version, creationTime, this)

    /**
     * Build a fresh, custom [OpenPGPKey] using PGPainless' API.
     *
     * @param version [OpenPGPKeyVersion]
     * @return [KeyRingBuilder] api
     */
    @JvmOverloads
    fun buildKey(
        version: OpenPGPKeyVersion = algorithmPolicy.keyGenerationAlgorithmSuite.keyVersion
    ): KeyRingBuilder = KeyRingBuilder(version, this)

    /**
     * Build a fresh, custom [OpenPGPKey] using BCs new API.
     *
     * @param version [OpenPGPKeyVersion]
     * @param creationTime creation time of the key, defaults to now
     * @return [OpenPGPKeyGenerator] api
     */
    @JvmOverloads
    fun _buildKey(
        version: OpenPGPKeyVersion = algorithmPolicy.keyGenerationAlgorithmSuite.keyVersion,
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
            instance ?: synchronized(this) { instance ?: createInstance().also { instance = it } }

        @JvmStatic
        fun setInstance(api: PGPainless) {
            instance = api
        }

        @JvmStatic fun createInstance() = PGPainless()

        @JvmStatic
        @JvmOverloads
        fun createLegacyInstance(
            implementation: OpenPGPImplementation = OpenPGPImplementation.getInstance()
        ) =
            PGPainless(
                implementation,
                Policy()
                    .copy()
                    .withKeyGenerationAlgorithmSuite(
                        AlgorithmSuite.emptyBuilder()
                            .overrideFeatures(Feature.MODIFICATION_DETECTION)
                            .overrideAeadAlgorithms(null)
                            .overrideHashAlgorithms(
                                HashAlgorithm.SHA512,
                                HashAlgorithm.SHA384,
                                HashAlgorithm.SHA256,
                                HashAlgorithm.SHA224)
                            .overrideSymmetricKeyAlgorithms(
                                SymmetricKeyAlgorithm.AES_256,
                                SymmetricKeyAlgorithm.AES_192,
                                SymmetricKeyAlgorithm.AES_128)
                            .overrideCompressionAlgorithms(
                                CompressionAlgorithm.ZLIB,
                                CompressionAlgorithm.BZIP2,
                                CompressionAlgorithm.ZIP,
                                CompressionAlgorithm.UNCOMPRESSED)
                            .overrideKeyVersion(OpenPGPKeyVersion.v4)
                            .build())
                    .build())
    }
}
