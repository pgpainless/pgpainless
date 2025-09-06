// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification

import java.io.IOException
import java.io.InputStream
import java.util.*
import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.api.OpenPGPKeyMaterialProvider.OpenPGPCertificateProvider
import org.bouncycastle.openpgp.api.OpenPGPSignature.OpenPGPDocumentSignature
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory
import org.pgpainless.PGPainless
import org.pgpainless.decryption_verification.cleartext_signatures.InMemoryMultiPassStrategy
import org.pgpainless.decryption_verification.cleartext_signatures.MultiPassStrategy
import org.pgpainless.key.SubkeyIdentifier
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.signature.SignatureUtils
import org.pgpainless.util.Passphrase
import org.pgpainless.util.SessionKey

/** Options for decryption and signature verification. */
class ConsumerOptions(private val api: PGPainless) {

    private var ignoreMDCErrors = false
    var isDisableAsciiArmorCRC = false
    private var forceNonOpenPgpData = false
    private var verifyNotBefore: Date? = null
    private var verifyNotAfter: Date? = Date()

    private val certificates = CertificateSource(api)
    private val detachedSignatures = mutableSetOf<PGPSignature>()
    private var missingCertificateCallback: OpenPGPCertificateProvider? = null

    private var sessionKey: SessionKey? = null
    private val customDecryptorFactories =
        mutableMapOf<KeyIdentifier, PublicKeyDataDecryptorFactory>()
    private val decryptionKeys = mutableMapOf<OpenPGPKey, SecretKeyRingProtector>()
    private val decryptionPassphrases = mutableSetOf<Passphrase>()
    private var missingKeyPassphraseStrategy = MissingKeyPassphraseStrategy.INTERACTIVE
    private var multiPassStrategy: MultiPassStrategy = InMemoryMultiPassStrategy()
    private var allowDecryptionWithNonEncryptionKey: Boolean = false

    /**
     * Consider signatures on the message made before the given timestamp invalid. Null means no
     * limitation.
     *
     * @param timestamp timestamp
     * @return options
     */
    fun verifyNotBefore(timestamp: Date?): ConsumerOptions = apply {
        this.verifyNotBefore = timestamp
    }

    fun getVerifyNotBefore() = verifyNotBefore

    /**
     * Consider signatures on the message made after the given timestamp invalid. Null means no
     * limitation.
     *
     * @param timestamp timestamp
     * @return options
     */
    fun verifyNotAfter(timestamp: Date?): ConsumerOptions = apply {
        this.verifyNotAfter = timestamp
    }

    fun getVerifyNotAfter() = verifyNotAfter

    fun addVerificationCert(verificationCert: OpenPGPCertificate): ConsumerOptions = apply {
        this.certificates.addCertificate(verificationCert)
    }

    fun addVerificationCerts(verificationCerts: Collection<OpenPGPCertificate>): ConsumerOptions =
        apply {
            for (cert in verificationCerts) {
                addVerificationCert(cert)
            }
        }

    /**
     * Add a certificate (public key ring) for signature verification.
     *
     * @param verificationCert certificate for signature verification
     * @return options
     */
    @Deprecated("Pass OpenPGPCertificate instead.")
    fun addVerificationCert(verificationCert: PGPPublicKeyRing): ConsumerOptions = apply {
        this.certificates.addCertificate(api.toCertificate(verificationCert))
    }

    /**
     * Add a set of certificates (public key rings) for signature verification.
     *
     * @param verificationCerts certificates for signature verification
     * @return options
     */
    @Deprecated("Use of methods taking PGPPublicKeyRingCollections is discouraged.")
    fun addVerificationCerts(verificationCerts: PGPPublicKeyRingCollection): ConsumerOptions =
        apply {
            for (cert in verificationCerts) {
                addVerificationCert(api.toCertificate(cert))
            }
        }

    /**
     * Add some detached signatures from the given [InputStream] for verification.
     *
     * @param signatureInputStream input stream of detached signatures
     * @return options
     * @throws IOException in case of an IO error
     * @throws PGPException in case of an OpenPGP error
     */
    @Throws(IOException::class, PGPException::class)
    fun addVerificationOfDetachedSignatures(signatureInputStream: InputStream): ConsumerOptions =
        apply {
            val signatures = SignatureUtils.readSignatures(signatureInputStream)
            addVerificationOfDetachedSignatures(signatures)
        }

    /**
     * Add some detached signatures for verification.
     *
     * @param detachedSignatures detached signatures
     * @return options
     */
    fun addVerificationOfDetachedSignatures(
        detachedSignatures: List<PGPSignature>
    ): ConsumerOptions = apply {
        for (signature in detachedSignatures) {
            addVerificationOfDetachedSignature(signature)
        }
    }

    fun addVerificationOfDetachedSignature(signature: OpenPGPDocumentSignature): ConsumerOptions =
        apply {
            if (signature.issuerCertificate != null) {
                addVerificationCert(signature.issuerCertificate)
            }
            addVerificationOfDetachedSignature(signature.signature)
        }

    /**
     * Add a detached signature for the signature verification process.
     *
     * @param detachedSignature detached signature
     * @return options
     */
    fun addVerificationOfDetachedSignature(detachedSignature: PGPSignature): ConsumerOptions =
        apply {
            detachedSignatures.add(detachedSignature)
        }

    fun getDetachedSignatures() = detachedSignatures.toList()

    /**
     * Set a callback that's used when a certificate (public key) is missing for signature
     * verification.
     *
     * @param callback callback
     * @return options
     */
    fun setMissingCertificateCallback(callback: OpenPGPCertificateProvider): ConsumerOptions =
        apply {
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

    @JvmOverloads
    fun addDecryptionKey(
        key: OpenPGPKey,
        protector: SecretKeyRingProtector = SecretKeyRingProtector.unprotectedKeys()
    ) = apply { decryptionKeys[key] = protector }

    /**
     * Add a key for message decryption. If the key is encrypted, the [SecretKeyRingProtector] is
     * used to decrypt it when needed.
     *
     * @param key key
     * @param protector protector for the secret key
     * @return options
     */
    @JvmOverloads
    @Deprecated("Pass OpenPGPKey instead.")
    fun addDecryptionKey(
        key: PGPSecretKeyRing,
        protector: SecretKeyRingProtector = SecretKeyRingProtector.unprotectedKeys()
    ) = addDecryptionKey(api.toKey(key), protector)

    /**
     * Add the keys in the provided key collection for message decryption.
     *
     * @param keys key collection
     * @param protector protector for encrypted secret keys
     * @return options
     */
    @JvmOverloads
    @Deprecated("Pass OpenPGPKey instances instead.")
    fun addDecryptionKeys(
        keys: PGPSecretKeyRingCollection,
        protector: SecretKeyRingProtector = SecretKeyRingProtector.unprotectedKeys()
    ) = apply {
        for (key in keys) {
            addDecryptionKey(api.toKey(key), protector)
        }
    }

    /**
     * Add a passphrase for message decryption. This passphrase will be used to try to decrypt
     * messages which were symmetrically encrypted for a passphrase.
     *
     * See
     * [Symmetrically Encrypted Data Packet](https://datatracker.ietf.org/doc/html/rfc4880#section-5.7)
     *
     * @param passphrase passphrase
     * @return options
     */
    fun addMessagePassphrase(passphrase: Passphrase) = apply {
        decryptionPassphrases.add(passphrase)
    }

    /**
     * Add a custom [PublicKeyDataDecryptorFactory] which enable decryption of messages, e.g. using
     * hardware-backed secret keys. (See e.g.
     * [org.pgpainless.decryption_verification.HardwareSecurity.HardwareDataDecryptorFactory]).
     *
     * @param factory decryptor factory
     * @return options
     */
    fun addCustomDecryptorFactory(factory: CustomPublicKeyDataDecryptorFactory) = apply {
        customDecryptorFactories[factory.keyIdentifier] = factory
    }

    /**
     * Return the custom [PublicKeyDataDecryptorFactory] that were set by the user. These factories
     * can be used to decrypt session keys using a custom logic.
     *
     * @return custom decryptor factories
     */
    fun getCustomDecryptorFactories() = customDecryptorFactories.toMap()

    /**
     * Return the set of available decryption keys.
     *
     * @return decryption keys
     */
    fun getDecryptionKeys(): Set<OpenPGPKey> = decryptionKeys.keys.toSet()

    /**
     * Return the set of available message decryption passphrases.
     *
     * @return decryption passphrases
     */
    fun getDecryptionPassphrases(): Set<Passphrase> = decryptionPassphrases.toSet()

    /**
     * Return an object holding available certificates for signature verification.
     *
     * @return certificate source
     */
    fun getCertificateSource(): CertificateSource = certificates

    /**
     * Return the callback that gets called when a certificate for signature verification is
     * missing. This method might return `null` if the users hasn't set a callback.
     *
     * @return missing public key callback
     */
    fun getMissingCertificateCallback(): OpenPGPCertificateProvider? = missingCertificateCallback

    /**
     * Return the [SecretKeyRingProtector] for the given [PGPSecretKeyRing].
     *
     * @param decryptionKeyRing secret key
     * @return protector for that particular secret key
     */
    fun getSecretKeyProtector(decryptionKeyRing: OpenPGPKey): SecretKeyRingProtector? {
        return decryptionKeys[decryptionKeyRing]
    }

    /**
     * By default, PGPainless will require encrypted messages to make use of SEIP data packets.
     * Those are Symmetrically Encrypted Integrity Protected Data packets. Symmetrically Encrypted
     * Data Packets without integrity protection are rejected by default. Furthermore, PGPainless
     * will throw an exception if verification of the MDC error detection code of the SEIP packet
     * fails.
     *
     * Failure of MDC verification indicates a tampered ciphertext, which might be the cause of an
     * attack or data corruption.
     *
     * This method can be used to ignore MDC errors and allow PGPainless to consume encrypted data
     * without integrity protection. If the flag <pre>ignoreMDCErrors</pre> is set to true,
     * PGPainless will
     * * not throw exceptions for SEIP packets with tampered ciphertext
     * * not throw exceptions for SEIP packets with tampered MDC
     * * not throw exceptions for MDCs with bad CTB
     * * not throw exceptions for MDCs with bad length
     *
     * It will however still throw an exception if it encounters a SEIP packet with missing or
     * truncated MDC
     *
     * See
     * [Sym. Encrypted Integrity Protected Data Packet](https://datatracker.ietf.org/doc/html/rfc4880.section-5.13)
     *
     * @param ignoreMDCErrors true if MDC errors or missing MDCs shall be ignored, false otherwise.
     * @return options
     */
    @Deprecated("Ignoring non-integrity-protected packets is discouraged.")
    fun setIgnoreMDCErrors(ignoreMDCErrors: Boolean): ConsumerOptions = apply {
        this.ignoreMDCErrors = ignoreMDCErrors
    }

    fun isIgnoreMDCErrors(): Boolean = ignoreMDCErrors

    fun setAllowDecryptionWithMissingKeyFlags(): ConsumerOptions = apply {
        allowDecryptionWithNonEncryptionKey = true
    }

    fun getAllowDecryptionWithNonEncryptionKey(): Boolean {
        return allowDecryptionWithNonEncryptionKey
    }

    /**
     * Force PGPainless to handle the data provided by the [InputStream] as non-OpenPGP data. This
     * workaround might come in handy if PGPainless accidentally mistakes the data for binary
     * OpenPGP data.
     *
     * @return options
     */
    fun forceNonOpenPgpData(): ConsumerOptions = apply { this.forceNonOpenPgpData = true }

    /**
     * Return true, if the ciphertext should be handled as binary non-OpenPGP data.
     *
     * @return true if non-OpenPGP data is forced
     */
    fun isForceNonOpenPgpData(): Boolean = forceNonOpenPgpData

    /**
     * Specify the [MissingKeyPassphraseStrategy]. This strategy defines, how missing passphrases
     * for unlocking secret keys are handled. In interactive mode
     * ([MissingKeyPassphraseStrategy.INTERACTIVE]) PGPainless will try to obtain missing
     * passphrases for secret keys via the [SecretKeyRingProtector]
     * [org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider] callback.
     *
     * In non-interactice mode ([MissingKeyPassphraseStrategy.THROW_EXCEPTION]), PGPainless will
     * instead throw a [org.pgpainless.exception.MissingPassphraseException] containing the ids of
     * all keys for which there are missing passphrases.
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
     * Set a custom multi-pass strategy for processing cleartext-signed messages. Uses
     * [InMemoryMultiPassStrategy] by default.
     *
     * @param multiPassStrategy multi-pass caching strategy
     * @return builder
     */
    fun setMultiPassStrategy(multiPassStrategy: MultiPassStrategy): ConsumerOptions {
        this.multiPassStrategy = multiPassStrategy
        return this
    }

    /**
     * Return the currently configured [MultiPassStrategy]. Defaults to [InMemoryMultiPassStrategy].
     *
     * @return multi-pass strategy
     */
    fun getMultiPassStrategy(): MultiPassStrategy {
        return multiPassStrategy
    }

    /**
     * Source for OpenPGP certificates. When verifying signatures on a message, this object holds
     * available signer certificates.
     */
    class CertificateSource(private val api: PGPainless) {
        private val explicitCertificates: MutableSet<OpenPGPCertificate> = mutableSetOf()

        /**
         * Add a certificate as verification cert explicitly.
         *
         * @param certificate certificate
         */
        @Deprecated("Pass in an OpenPGPCertificate instead.")
        fun addCertificate(certificate: PGPPublicKeyRing) {
            explicitCertificates.add(api.toCertificate(certificate))
        }

        /**
         * Add a certificate as explicitly provided verification cert.
         *
         * @param certificate explicit verification cert
         */
        fun addCertificate(certificate: OpenPGPCertificate) {
            explicitCertificates.add(certificate)
        }

        /**
         * Return the set of explicitly set verification certificates.
         *
         * @return explicitly set verification certs
         */
        fun getExplicitCertificates(): Set<OpenPGPCertificate> {
            return explicitCertificates.toSet()
        }

        /**
         * Return a certificate which contains a subkey with the given keyId. This method first
         * checks all explicitly set verification certs and if no cert is found it consults the
         * certificate stores.
         *
         * @param keyId key id
         * @return certificate
         */
        @Deprecated("Pass in a KeyIdentifier instead.")
        fun getCertificate(keyId: Long): OpenPGPCertificate? {
            return getCertificate(KeyIdentifier(keyId))
        }

        /**
         * Return a certificate which contains a component key for the given [identifier]. This
         * method first checks all explicitly provided verification certs and if no cert is found it
         * consults the certificate stores.
         *
         * @param identifier key identifier
         * @return certificate or null if no match is found
         */
        fun getCertificate(identifier: KeyIdentifier): OpenPGPCertificate? {
            return explicitCertificates.firstOrNull { it.getKey(identifier) != null }
        }

        /** Find a certificate containing the issuer component key for the given [signature]. */
        fun getCertificate(signature: PGPSignature): OpenPGPCertificate? =
            explicitCertificates.firstOrNull { it.getSigningKeyFor(signature) != null }
    }

    companion object {
        @JvmOverloads
        @JvmStatic
        fun get(api: PGPainless = PGPainless.getInstance()) = ConsumerOptions(api)
    }
}
