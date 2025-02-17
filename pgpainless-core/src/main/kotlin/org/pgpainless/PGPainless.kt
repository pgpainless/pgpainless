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
import org.bouncycastle.openpgp.api.OpenPGPKeyReader
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi
import org.pgpainless.algorithm.OpenPGPKeyVersion
import org.pgpainless.bouncycastle.PolicyAdapter
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
    val algorithmPolicy: Policy = Policy.getInstance()
) {

    private var api: OpenPGPApi

    init {
        implementation.setPolicy(
            PolicyAdapter(algorithmPolicy)) // adapt PGPainless' Policy to BCs OpenPGPPolicy
        api = BcOpenPGPApi(implementation)
    }

    fun generateKey(version: OpenPGPKeyVersion = OpenPGPKeyVersion.v4): KeyRingTemplates =
        KeyRingTemplates(version)

    fun readKey(): OpenPGPKeyReader = api.readKeyOrCertificate()

    fun toKey(secretKeyRing: PGPSecretKeyRing): OpenPGPKey =
        OpenPGPKey(secretKeyRing, implementation)

    fun toCertificate(publicKeyRing: PGPPublicKeyRing): OpenPGPCertificate =
        OpenPGPCertificate(publicKeyRing, implementation)

    companion object {

        @Volatile private var instance: PGPainless? = null

        @JvmStatic
        fun getInstance() =
            instance ?: synchronized(this) { instance ?: PGPainless().also { instance = it } }

        @JvmStatic
        fun setInstance(pgpainless: PGPainless) {
            instance = pgpainless
        }

        /**
         * Generate a fresh OpenPGP key ring from predefined templates.
         *
         * @return templates
         */
        @JvmStatic
        @JvmOverloads
        fun generateKeyRing(version: OpenPGPKeyVersion = OpenPGPKeyVersion.v4) =
            getInstance().generateKey(version)

        /**
         * Build a custom OpenPGP key ring.
         *
         * @return builder
         */
        @JvmStatic
        @JvmOverloads
        fun buildKeyRing(version: OpenPGPKeyVersion = OpenPGPKeyVersion.v4) =
            KeyRingBuilder(version, getInstance().implementation)

        /**
         * Read an existing OpenPGP key ring.
         *
         * @return builder
         */
        @Deprecated("Use readKey() instead.", replaceWith = ReplaceWith("readKey()"))
        @JvmStatic
        fun readKeyRing() = KeyRingReader()

        /**
         * Extract a public key certificate from a secret key.
         *
         * @param secretKey secret key
         * @return public key certificate
         */
        @JvmStatic
        @Deprecated("Use toKey() and then .toCertificate() instead.")
        fun extractCertificate(secretKey: PGPSecretKeyRing) =
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
        fun mergeCertificate(originalCopy: PGPPublicKeyRing, updatedCopy: PGPPublicKeyRing) =
            PGPPublicKeyRing.join(originalCopy, updatedCopy)

        /**
         * Wrap a key or certificate in ASCII armor.
         *
         * @param key key or certificate
         * @return ascii armored string
         * @throws IOException in case of an error during the armoring process
         */
        @JvmStatic
        fun asciiArmor(key: PGPKeyRing) =
            if (key is PGPSecretKeyRing) ArmorUtils.toAsciiArmoredString(key)
            else ArmorUtils.toAsciiArmoredString(key as PGPPublicKeyRing)

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
        fun asciiArmor(signature: PGPSignature) = ArmorUtils.toAsciiArmoredString(signature)

        /**
         * Create an [EncryptionBuilder], which can be used to encrypt and/or sign data using
         * OpenPGP.
         *
         * @return builder
         */
        @JvmStatic fun encryptAndOrSign() = EncryptionBuilder()

        /**
         * Create a [DecryptionBuilder], which can be used to decrypt and/or verify data using
         * OpenPGP.
         *
         * @return builder
         */
        @JvmStatic fun decryptAndOrVerify() = DecryptionBuilder()

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
        fun modifyKeyRing(secretKey: PGPSecretKeyRing, referenceTime: Date = Date()) =
            SecretKeyRingEditor(secretKey, referenceTime)

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
        fun inspectKeyRing(key: PGPKeyRing, referenceTime: Date = Date()) =
            KeyRingInfo(key, referenceTime)

        fun inspectKeyRing(key: OpenPGPCertificate, referenceTime: Date = Date()) =
            KeyRingInfo(key, getPolicy(), referenceTime)

        /**
         * Access, and make changes to PGPainless policy on acceptable/default algorithms etc.
         *
         * @return policy
         */
        @JvmStatic fun getPolicy() = getInstance().algorithmPolicy

        /**
         * Create different kinds of signatures on other keys.
         *
         * @return builder
         */
        @JvmStatic fun certify() = CertifyCertificate()
    }
}
