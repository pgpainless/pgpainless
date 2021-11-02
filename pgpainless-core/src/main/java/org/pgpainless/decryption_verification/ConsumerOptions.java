// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.decryption_verification.cleartext_signatures.InMemoryMultiPassStrategy;
import org.pgpainless.decryption_verification.cleartext_signatures.MultiPassStrategy;
import org.pgpainless.exception.NotYetImplementedException;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.util.Passphrase;

/**
 * Options for decryption and signature verification.
 */
public class ConsumerOptions {


    private boolean ignoreMDCErrors = false;

    private Date verifyNotBefore = null;
    private Date verifyNotAfter = new Date();

    // Set of verification keys
    private final Set<PGPPublicKeyRing> certificates = new HashSet<>();
    private final Set<PGPSignature> detachedSignatures = new HashSet<>();
    private MissingPublicKeyCallback missingCertificateCallback = null;

    // Session key for decryption without passphrase/key
    private byte[] sessionKey = null;

    private final Map<PGPSecretKeyRing, SecretKeyRingProtector> decryptionKeys = new HashMap<>();
    private final Set<Passphrase> decryptionPassphrases = new HashSet<>();
    private MissingKeyPassphraseStrategy missingKeyPassphraseStrategy = MissingKeyPassphraseStrategy.INTERACTIVE;

    private MultiPassStrategy multiPassStrategy = new InMemoryMultiPassStrategy();

    /**
     * Consider signatures on the message made before the given timestamp invalid.
     * Null means no limitation.
     *
     * @param timestamp timestamp
     * @return options
     */
    public ConsumerOptions verifyNotBefore(Date timestamp) {
        this.verifyNotBefore = timestamp;
        return this;
    }

    /**
     * Return the earliest creation date on which signatures on the message are considered valid.
     * Signatures made earlier than this date are considered invalid.
     *
     * @return earliest allowed signature creation date or null
     */
    public @Nullable Date getVerifyNotBefore() {
        return verifyNotBefore;
    }

    /**
     * Consider signatures on the message made after the given timestamp invalid.
     * Null means no limitation.
     *
     * @param timestamp timestamp
     * @return options
     */
    public ConsumerOptions verifyNotAfter(Date timestamp) {
        this.verifyNotAfter = timestamp;
        return this;
    }

    /**
     * Return the latest possible creation date on which signatures made on the message are considered valid.
     * Signatures made later than this date are considered invalid.
     *
     * @return Latest possible creation date or null.
     */
    public Date getVerifyNotAfter() {
        return verifyNotAfter;
    }

    /**
     * Add a certificate (public key ring) for signature verification.
     *
     * @param verificationCert certificate for signature verification
     * @return options
     */
    public ConsumerOptions addVerificationCert(PGPPublicKeyRing verificationCert) {
        this.certificates.add(verificationCert);
        return this;
    }

    /**
     * Add a set of certificates (public key rings) for signature verification.
     *
     * @param verificationCerts certificates for signature verification
     * @return options
     */
    public ConsumerOptions addVerificationCerts(PGPPublicKeyRingCollection verificationCerts) {
        for (PGPPublicKeyRing certificate : verificationCerts) {
            addVerificationCert(certificate);
        }
        return this;
    }

    public ConsumerOptions addVerificationOfDetachedSignatures(InputStream signatureInputStream) throws IOException, PGPException {
        List<PGPSignature> signatures = SignatureUtils.readSignatures(signatureInputStream);
        return addVerificationOfDetachedSignatures(signatures);
    }

    public ConsumerOptions addVerificationOfDetachedSignatures(List<PGPSignature> detachedSignatures) {
        for (PGPSignature signature : detachedSignatures) {
            addVerificationOfDetachedSignature(signature);
        }
        return this;
    }

    /**
     * Add a detached signature for the signature verification process.
     *
     * @param detachedSignature detached signature
     * @return options
     */
    public ConsumerOptions addVerificationOfDetachedSignature(PGPSignature detachedSignature) {
        detachedSignatures.add(detachedSignature);
        return this;
    }

    /**
     * Set a callback that's used when a certificate (public key) is missing for signature verification.
     *
     * @param callback callback
     * @return options
     */
    public ConsumerOptions setMissingCertificateCallback(MissingPublicKeyCallback callback) {
        this.missingCertificateCallback = callback;
        return this;
    }


    /**
     * Attempt decryption using a session key.
     *
     * Note: PGPainless does not yet support decryption with session keys.
     * TODO: Add support for decryption using session key.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-2.1">RFC4880 on Session Keys</a>
     *
     * @param sessionKey session key
     * @return options
     */
    public ConsumerOptions setSessionKey(@Nonnull byte[] sessionKey) {
        this.sessionKey = sessionKey;
        throw new NotYetImplementedException();
    }

    /**
     * Return the session key.
     *
     * @return session key or null
     */
    public @Nullable byte[] getSessionKey() {
        if (sessionKey == null) {
            return null;
        }

        byte[] sk = new byte[sessionKey.length];
        System.arraycopy(sessionKey, 0, sk, 0, sessionKey.length);
        return sk;
    }

    /**
     * Add a key for message decryption.
     * The key is expected to be unencrypted.
     *
     * @param key unencrypted key
     * @return options
     */
    public ConsumerOptions addDecryptionKey(@Nonnull PGPSecretKeyRing key) {
        return addDecryptionKey(key, SecretKeyRingProtector.unprotectedKeys());
    }

    /**
     * Add a key for message decryption. If the key is encrypted, the {@link SecretKeyRingProtector} is used to decrypt it
     * when needed.
     *
     * @param key key
     * @param keyRingProtector protector for the secret key
     * @return options
     */
    public ConsumerOptions addDecryptionKey(@Nonnull PGPSecretKeyRing key, @Nonnull SecretKeyRingProtector keyRingProtector) {
        decryptionKeys.put(key, keyRingProtector);
        return this;
    }

    /**
     * Add the keys in the provided key collection for message decryption.
     *
     * @param keys key collection
     * @param keyRingProtector protector for encrypted secret keys
     * @return options
     */
    public ConsumerOptions addDecryptionKeys(@Nonnull PGPSecretKeyRingCollection keys, @Nonnull SecretKeyRingProtector keyRingProtector) {
        for (PGPSecretKeyRing key : keys) {
            addDecryptionKey(key, keyRingProtector);
        }
        return this;
    }

    /**
     * Add a passphrase for message decryption.
     * This passphrase will be used to try to decrypt messages which were symmetrically encrypted for a passphrase.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.7">Symmetrically Encrypted Data Packet</a>
     *
     * @param passphrase passphrase
     * @return options
     */
    public ConsumerOptions addDecryptionPassphrase(@Nonnull Passphrase passphrase) {
        decryptionPassphrases.add(passphrase);
        return this;
    }

    public @Nonnull Set<PGPSecretKeyRing> getDecryptionKeys() {
        return Collections.unmodifiableSet(decryptionKeys.keySet());
    }

    public @Nonnull Set<Passphrase> getDecryptionPassphrases() {
        return Collections.unmodifiableSet(decryptionPassphrases);
    }

    public @Nonnull Set<PGPPublicKeyRing> getCertificates() {
        return Collections.unmodifiableSet(certificates);
    }

    public @Nullable MissingPublicKeyCallback getMissingCertificateCallback() {
        return missingCertificateCallback;
    }

    public @Nonnull SecretKeyRingProtector getSecretKeyProtector(PGPSecretKeyRing decryptionKeyRing) {
        return decryptionKeys.get(decryptionKeyRing);
    }

    public @Nonnull Set<PGPSignature> getDetachedSignatures() {
        return Collections.unmodifiableSet(detachedSignatures);
    }

    /**
     * By default, PGPainless will require encrypted messages to make use of SEIP data packets.
     * Those are Symmetrically Encrypted Integrity Protected Data packets.
     * Symmetrically Encrypted Data Packets without integrity protection are rejected by default.
     * Furthermore, PGPainless will throw an exception if verification of the MDC error detection code of the SEIP packet
     * fails.
     *
     * Failure of MDC verification indicates a tampered ciphertext, which might be the cause of an attack or data corruption.
     *
     * This method can be used to ignore MDC errors and allow PGPainless to consume encrypted data without integrity protection.
     * If the flag <pre>ignoreMDCErrors</pre> is set to true, PGPainless will
     * <ul>
     *     <li>not throw exceptions for SEIP packets with tampered ciphertext</li>
     *     <li>not throw exceptions for SEIP packets with tampered MDC</li>
     *     <li>not throw exceptions for MDCs with bad CTB</li>
     *     <li>not throw exceptions for MDCs with bad length</li>
     * </ul>
     *
     * It will however still throw an exception if it encounters a SEIP packet with missing or truncated MDC
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.13">Sym. Encrypted Integrity Protected Data Packet</a>
     * @param ignoreMDCErrors true if MDC errors or missing MDCs shall be ignored, false otherwise.
     * @return options
     */
    @Deprecated
    public ConsumerOptions setIgnoreMDCErrors(boolean ignoreMDCErrors) {
        this.ignoreMDCErrors = ignoreMDCErrors;
        return this;
    }

    /**
     * Return true, if PGPainless is ignoring MDC errors.
     *
     * @return ignore mdc errors
     */
    boolean isIgnoreMDCErrors() {
        return ignoreMDCErrors;
    }

    /**
     * Specify the {@link MissingKeyPassphraseStrategy}.
     * This strategy defines, how missing passphrases for unlocking secret keys are handled.
     * In interactive mode ({@link MissingKeyPassphraseStrategy#INTERACTIVE}) PGPainless will try to obtain missing
     * passphrases for secret keys via the {@link SecretKeyRingProtector SecretKeyRingProtectors}
     * {@link org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider} callback.
     *
     * In non-interactice mode ({@link MissingKeyPassphraseStrategy#THROW_EXCEPTION}, PGPainless will instead
     * throw a {@link org.pgpainless.exception.MissingPassphraseException} containing the ids of all keys for which
     * there are missing passphrases.
     *
     * @param strategy strategy
     * @return options
     */
    public ConsumerOptions setMissingKeyPassphraseStrategy(MissingKeyPassphraseStrategy strategy) {
        this.missingKeyPassphraseStrategy = strategy;
        return this;
    }

    /**
     * Return the currently configured {@link MissingKeyPassphraseStrategy}.
     *
     * @return missing key passphrase strategy
     */
    MissingKeyPassphraseStrategy getMissingKeyPassphraseStrategy() {
        return missingKeyPassphraseStrategy;
    }

    /**
     * Set a custom multi-pass strategy for processing cleartext-signed messages.
     * Uses {@link InMemoryMultiPassStrategy} by default.
     *
     * @param multiPassStrategy multi-pass caching strategy
     * @return builder
     */
    public ConsumerOptions setMultiPassStrategy(@Nonnull MultiPassStrategy multiPassStrategy) {
        this.multiPassStrategy = multiPassStrategy;
        return this;
    }

    /**
     * Return the currently configured {@link MultiPassStrategy}.
     * Defaults to {@link InMemoryMultiPassStrategy}.
     *
     * @return multi-pass strategy
     */
    public MultiPassStrategy getMultiPassStrategy() {
        return multiPassStrategy;
    }
}
