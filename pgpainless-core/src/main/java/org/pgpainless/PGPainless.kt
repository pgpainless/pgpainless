package org.pgpainless

import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
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
import java.io.OutputStream
import java.util.*

class PGPainless private constructor() {

    companion object {

        /**
         * Generate a fresh OpenPGP key ring from predefined templates.
         * @return templates
         */
        @JvmStatic
        fun generateKeyRing() = KeyRingTemplates()

        /**
         * Build a custom OpenPGP key ring.
         *
         * @return builder
         */
        @JvmStatic
        fun buildKeyRing() = KeyRingBuilder()

        /**
         * Read an existing OpenPGP key ring.
         * @return builder
         */
        @JvmStatic
        fun readKeyRing() = KeyRingReader()

        /**
         * Extract a public key certificate from a secret key.
         *
         * @param secretKey secret key
         * @return public key certificate
         */
        @JvmStatic
        fun extractCertificate(secretKey: PGPSecretKeyRing) =
                KeyRingUtils.publicKeyRingFrom(secretKey)

        /**
         * Merge two copies of the same certificate (e.g. an old copy, and one retrieved from a key server) together.
         *
         * @param originalCopy local, older copy of the cert
         * @param updatedCopy updated, newer copy of the cert
         * @return merged certificate
         * @throws PGPException in case of an error
         */
        @JvmStatic
        fun mergeCertificate(originalCopy: PGPPublicKeyRing,
                             updatedCopy: PGPPublicKeyRing) =
                PGPPublicKeyRing.join(originalCopy, updatedCopy)

        /**
         * Wrap a key or certificate in ASCII armor.
         *
         * @param key key or certificate
         * @return ascii armored string
         *
         * @throws IOException in case of an error during the armoring process
         */
        @JvmStatic
        fun asciiArmor(key: PGPKeyRing) =
                if (key is PGPSecretKeyRing)
                    ArmorUtils.toAsciiArmoredString(key)
                else
                    ArmorUtils.toAsciiArmoredString(key as PGPPublicKeyRing)

        /**
         * Wrap a key of certificate in ASCII armor and write the result into the given [OutputStream].
         *
         * @param key key or certificate
         * @param outputStream output stream
         *
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
         *
         * @throws IOException in case of an error during the armoring process
         */
        @JvmStatic
        fun asciiArmor(signature: PGPSignature) = ArmorUtils.toAsciiArmoredString(signature)

        /**
         * Create an [EncryptionBuilder], which can be used to encrypt and/or sign data using OpenPGP.
         *
         * @return builder
         */
        @JvmStatic
        fun encryptAndOrSign() = EncryptionBuilder()

        /**
         * Create a [DecryptionBuilder], which can be used to decrypt and/or verify data using OpenPGP.
         *
         * @return builder
         */
        @JvmStatic
        fun decryptAndOrVerify() = DecryptionBuilder()

        /**
         * Make changes to a secret key at the given reference time.
         * This method can be used to change key expiration dates and passphrases, or add/revoke user-ids and subkeys.
         * <p>
         * After making the desired changes in the builder, the modified key can be extracted using {@link SecretKeyRingEditorInterface#done()}.
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
         * Quickly access information about a [org.bouncycastle.openpgp.PGPPublicKeyRing] / [PGPSecretKeyRing].
         * This method can be used to determine expiration dates, key flags and other information about a key at a specific time.
         *
         * @param keyRing key ring
         * @param referenceTime date of inspection
         * @return access object
         */
        @JvmStatic
        @JvmOverloads
        fun inspectKeyRing(key: PGPKeyRing, referenceTime: Date = Date()) =
                KeyRingInfo(key, referenceTime)

        /**
         * Access, and make changes to PGPainless policy on acceptable/default algorithms etc.
         *
         * @return policy
         */
        @JvmStatic
        fun getPolicy() = Policy.getInstance()

        /**
         * Create different kinds of signatures on other keys.
         *
         * @return builder
         */
        @JvmStatic
        fun certify() = CertifyCertificate()
    }
}