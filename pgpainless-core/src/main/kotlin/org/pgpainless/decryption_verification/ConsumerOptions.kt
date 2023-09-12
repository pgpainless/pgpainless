// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification

import org.bouncycastle.extensions.getPublicKeyFor
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory
import org.pgpainless.decryption_verification.cleartext_signatures.InMemoryMultiPassStrategy
import org.pgpainless.decryption_verification.cleartext_signatures.MultiPassStrategy
import org.pgpainless.key.SubkeyIdentifier
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.signature.SignatureUtils
import org.pgpainless.util.Passphrase
import org.pgpainless.util.SessionKey
import java.io.IOException
import java.io.InputStream
import java.util.*

/**
 * Options for decryption and signature verification.
 */
class ConsumerOptions {

    private var ignoreMDCErrors = false
    private var forceNonOpenPgpData = false
    private var verifyNotBefore: Date? = null
    private var verifyNotAfter: Date? = Date()

    private val certificates = CertificateSource()
    private val detachedSignatures = mutableSetOf<PGPSignature>()
    private var missingCertificateCallback: MissingPublicKeyCallback? = null

    private var sessionKey: SessionKey? = null
    private val customDecryptorFactories = mutableMapOf<SubkeyIdentifier, PublicKeyDataDecryptorFactory>()
    private val decryptionKeys = mutableMapOf<PGPSecretKeyRing, SecretKeyRingProtector>()
    private val decryptionPassphrases = mutableSetOf<Passphrase>()
    private var missingKeyPassphraseStrategy = MissingKeyPassphraseStrategy.INTERACTIVE
    private var multiPassStrategy: MultiPassStrategy = InMemoryMultiPassStrategy()

    /**
     * Consider signatures on the message made before the given timestamp invalid.
     * Null means no limitation.
     *
     * @param timestamp timestamp
     * @return options
     */
    fun verifyNotBefore(timestamp: Date?): ConsumerOptions = apply {
        this.verifyNotBefore = timestamp
    }

    fun getVerifyNotBefore() = verifyNotBefore

    /**
     * Consider signatures on the message made after the given timestamp invalid.
     * Null means no limitation.
     *
     * @param timestamp timestamp
     * @return options
     */
    fun verifyNotAfter(timestamp: Date?): ConsumerOptions = apply {
        this.verifyNotAfter = timestamp
    }

    fun getVerifyNotAfter() = verifyNotAfter

    /**
     * Add a certificate (public key ring) for signature verification.
     *
     * @param verificationCert certificate for signature verification
     * @return options
     */
    fun addVerificationCert(verificationCert: PGPPublicKeyRing): ConsumerOptions = apply {
        this.certificates.addCertificate(verificationCert)
    }

    /**
     * Add a set of certificates (public key rings) for signature verification.
     *
     * @param verificationCerts certificates for signature verification
     * @return options
     */
    fun addVerificationCerts(verificationCerts: PGPPublicKeyRingCollection): ConsumerOptions = apply {
        for (cert in verificationCerts) {
            addVerificationCert(cert)
        }
    }

    /**
     * Add some detached signatures from the given [InputStream] for verification.
     *
     * @param signatureInputStream input stream of detached signatures
     * @return options
     *
     * @throws IOException in case of an IO error
     * @throws PGPException in case of an OpenPGP error
     */
    @Throws(IOException::class, PGPException::class)
    fun addVerificationOfDetachedSignatures(signatureInputStream: InputStream): ConsumerOptions = apply {
        val signatures = SignatureUtils.readSignatures(signatureInputStream)
        addVerificationOfDetachedSignatures(signatures)
    }

    /**
     * Add some detached signatures for verification.
     *
     * @param detachedSignatures detached signatures
     * @return options
     */
    fun addVerificationOfDetachedSignatures(detachedSignatures: List<PGPSignature>): ConsumerOptions = apply {
        for (signature in detachedSignatures) {
            addVerificationOfDetachedSignature(signature)
        }
    }

    /**
     * Add a detached signature for the signature verification process.
     *
     * @param detachedSignature detached signature
     * @return options
     */
    fun addVerificationOfDetachedSignature(detachedSignature: PGPSignature): ConsumerOptions = apply {
        detachedSignatures.add(detachedSignature)
    }

    fun getDetachedSignatures() = detachedSignatures.toList()

    /**
     * Set a callback that's used when a certificate (public key) is missing for signature verification.
     *
     * @param callback callback
     * @return options
     */
    fun setMissingCertificateCallback(callback: MissingPublicKeyCallback): ConsumerOptions = apply {
        this.missingCertificateCallback = callback
    }

    /**
     * Attempt decryption using a session key.
     *
     * Note: PGPainless does not yet support decryption with session keys.
     *
     * See [RFC4880 on Session Keys](https://datatracker.ietf.org/doc/html/rfc4880#section-2.1)
     *
     * @param sessionKey session key
     * @return options
     */
    fun setSessionKey(sessionKey: SessionKey) = apply { this.sessionKey = sessionKey }

    fun getSessionKey() = sessionKey

    /**
     * Add a key for message decryption. If the key is encrypted, the [SecretKeyRingProtector]
     * is used to decrypt it when needed.
     *
     * @param key key
     * @param keyRingProtector protector for the secret key
     * @return options
     */
    @JvmOverloads
    fun addDecryptionKey(key: PGPSecretKeyRing,
                         protector: SecretKeyRingProtector = SecretKeyRingProtector.unprotectedKeys()) = apply {
        decryptionKeys[key] = protector
    }

    /**
     * Add the keys in the provided key collection for message decryption.
     *
     * @param keys key collection
     * @param keyRingProtector protector for encrypted secret keys
     * @return options
     */
    @JvmOverloads
    fun addDecryptionKeys(keys: PGPSecretKeyRingCollection,
                          protector: SecretKeyRingProtector = SecretKeyRingProtector.unprotectedKeys()) = apply {
        for (key in keys) {
            addDecryptionKey(key, protector)
        }
    }

    /**
     * Add a passphrase for message decryption.
     * This passphrase will be used to try to decrypt messages which were symmetrically encrypted for a passphrase.
     *
     * See [Symmetrically Encrypted Data Packet](https://datatracker.ietf.org/doc/html/rfc4880#section-5.7)
     *
     * @param passphrase passphrase
     * @return options
     */
    fun addDecryptionPassphrase(passphrase: Passphrase) = apply {
        decryptionPassphrases.add(passphrase)
    }

    /**
     * Add a custom [PublicKeyDataDecryptorFactory] which enable decryption of messages, e.g. using
     * hardware-backed secret keys.
     * (See e.g. [org.pgpainless.decryption_verification.HardwareSecurity.HardwareDataDecryptorFactory]).
     *
     * @param factory decryptor factory
     * @return options
     */
    fun addCustomDecryptorFactory(factory: CustomPublicKeyDataDecryptorFactory) = apply {
        customDecryptorFactories[factory.subkeyIdentifier] = factory
    }

    /**
     * Return the custom [PublicKeyDataDecryptorFactory] that were
     * set by the user.
     * These factories can be used to decrypt session keys using a custom logic.
     *
     * @return custom decryptor factories
     */
    fun getCustomDecryptorFactories() = customDecryptorFactories.toMap()

    /**
     * Return the set of available decryption keys.
     *
     * @return decryption keys
     */
    fun getDecryptionKeys() = decryptionKeys.keys.toSet()

    /**
     * Return the set of available message decryption passphrases.
     *
     * @return decryption passphrases
     */
    fun getDecryptionPassphrases() = decryptionPassphrases.toSet()

    /**
     * Return an object holding available certificates for signature verification.
     *
     * @return certificate source
     */
    fun getCertificateSource() = certificates

    /**
     * Return the callback that gets called when a certificate for signature verification is missing.
     * This method might return `null` if the users hasn't set a callback.
     *
     * @return missing public key callback
     */
    fun getMissingCertificateCallback() = missingCertificateCallback

    /**
     * Return the [SecretKeyRingProtector] for the given [PGPSecretKeyRing].
     *
     * @param decryptionKeyRing secret key
     * @return protector for that particular secret key
     */
    fun getSecretKeyProtector(decryptionKeyRing: PGPSecretKeyRing): SecretKeyRingProtector? {
        return decryptionKeys[decryptionKeyRing]
    }

    /**
     * By default, PGPainless will require encrypted messages to make use of SEIP data packets.
     * Those are Symmetrically Encrypted Integrity Protected Data packets.
     * Symmetrically Encrypted Data Packets without integrity protection are rejected by default.
     * Furthermore, PGPainless will throw an exception if verification of the MDC error detection
     * code of the SEIP packet fails.
     *
     * Failure of MDC verification indicates a tampered ciphertext, which might be the cause of an
     * attack or data corruption.
     *
     * This method can be used to ignore MDC errors and allow PGPainless to consume encrypted data
     * without integrity protection.
     * If the flag <pre>ignoreMDCErrors</pre> is set to true, PGPainless will
     *
     *  * not throw exceptions for SEIP packets with tampered ciphertext
     *  * not throw exceptions for SEIP packets with tampered MDC
     *  * not throw exceptions for MDCs with bad CTB
     *  * not throw exceptions for MDCs with bad length
     *
     *
     * It will however still throw an exception if it encounters a SEIP packet with missing or truncated MDC
     *
     * See [Sym. Encrypted Integrity Protected Data Packet](https://datatracker.ietf.org/doc/html/rfc4880.section-5.13)
     *
     * @param ignoreMDCErrors true if MDC errors or missing MDCs shall be ignored, false otherwise.
     * @return options
     */
    @Deprecated("Ignoring non-integrity-protected packets is discouraged.")
    fun setIgnoreMDCErrors(ignoreMDCErrors: Boolean): ConsumerOptions = apply { this.ignoreMDCErrors = ignoreMDCErrors }

    fun isIgnoreMDCErrors() = ignoreMDCErrors

    /**
     * Force PGPainless to handle the data provided by the [InputStream] as non-OpenPGP data.
     * This workaround might come in handy if PGPainless accidentally mistakes the data for binary OpenPGP data.
     *
     * @return options
     */
    fun forceNonOpenPgpData(): ConsumerOptions = apply {
        this.forceNonOpenPgpData = true
    }

    /**
     * Return true, if the ciphertext should be handled as binary non-OpenPGP data.
     *
     * @return true if non-OpenPGP data is forced
     */
    fun isForceNonOpenPgpData() = forceNonOpenPgpData

    /**
     * Specify the [MissingKeyPassphraseStrategy].
     * This strategy defines, how missing passphrases for unlocking secret keys are handled.
     * In interactive mode ([MissingKeyPassphraseStrategy.INTERACTIVE]) PGPainless will try to obtain missing
     * passphrases for secret keys via the [SecretKeyRingProtector]
     * [org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider] callback.
     *
     * In non-interactice mode ([MissingKeyPassphraseStrategy.THROW_EXCEPTION]), PGPainless will instead
     * throw a [org.pgpainless.exception.MissingPassphraseException] containing the ids of all keys for which
     * there are missing passphrases.
     *
     * @param strategy strategy
     * @return options
     */
    fun setMissingKeyPassphraseStrategy(strategy: MissingKeyPassphraseStrategy): ConsumerOptions {
        this.missingKeyPassphraseStrategy = strategy
        return this
    }

    /**
     * Return the currently configured [MissingKeyPassphraseStrategy].
     *
     * @return missing key passphrase strategy
     */
    fun getMissingKeyPassphraseStrategy(): MissingKeyPassphraseStrategy {
        return missingKeyPassphraseStrategy
    }

    /**
     * Set a custom multi-pass strategy for processing cleartext-signed messages.
     * Uses [InMemoryMultiPassStrategy] by default.
     *
     * @param multiPassStrategy multi-pass caching strategy
     * @return builder
     */
    fun setMultiPassStrategy(multiPassStrategy: MultiPassStrategy): ConsumerOptions {
        this.multiPassStrategy = multiPassStrategy
        return this
    }

    /**
     * Return the currently configured [MultiPassStrategy].
     * Defaults to [InMemoryMultiPassStrategy].
     *
     * @return multi-pass strategy
     */
    fun getMultiPassStrategy(): MultiPassStrategy {
        return multiPassStrategy
    }

    /**
     * Source for OpenPGP certificates.
     * When verifying signatures on a message, this object holds available signer certificates.
     */
    class CertificateSource {
        private val explicitCertificates: MutableSet<PGPPublicKeyRing> = mutableSetOf()

        /**
         * Add a certificate as verification cert explicitly.
         *
         * @param certificate certificate
         */
        fun addCertificate(certificate: PGPPublicKeyRing) {
            explicitCertificates.add(certificate)
        }

        /**
         * Return the set of explicitly set verification certificates.
         * @return explicitly set verification certs
         */
        fun getExplicitCertificates(): Set<PGPPublicKeyRing> {
            return explicitCertificates.toSet()
        }

        /**
         * Return a certificate which contains a subkey with the given keyId.
         * This method first checks all explicitly set verification certs and if no cert is found it consults
         * the certificate stores.
         *
         * @param keyId key id
         * @return certificate
         */
        fun getCertificate(keyId: Long): PGPPublicKeyRing? {
            return explicitCertificates.firstOrNull { it.getPublicKey(keyId) != null }
        }

        fun getCertificate(signature: PGPSignature): PGPPublicKeyRing? =
                explicitCertificates.firstOrNull {
                    it.getPublicKeyFor(signature) != null
                }
    }

    companion object {
        @JvmStatic
        fun get() = ConsumerOptions()
    }
}