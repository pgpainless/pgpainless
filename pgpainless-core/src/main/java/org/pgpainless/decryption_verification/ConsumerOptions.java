/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.decryption_verification;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;

/**
 * Options for decryption and signature verification.
 */
public class ConsumerOptions {

    private Date verifyNotBefore;
    private Date verifyNotAfter;

    // Set of verification keys
    private final Set<PGPPublicKeyRing> certificates = new HashSet<>();
    private final Set<PGPSignature> detachedSignatures = new HashSet<>();
    private MissingPublicKeyCallback missingCertificateCallback = null;

    // Session key for decryption without passphrase/key
    private byte[] sessionKey = null;

    private final Map<PGPSecretKeyRing, SecretKeyRingProtector> decryptionKeys = new HashMap<>();
    private final Set<Passphrase> decryptionPassphrases = new HashSet<>();


    /**
     * Consider signatures made before the given timestamp invalid.
     *
     * @param timestamp timestamp
     * @return options
     */
    public ConsumerOptions verifyNotBefore(Date timestamp) {
        this.verifyNotBefore = timestamp;
        return this;
    }

    public Date getVerifyNotBefore() {
        return verifyNotBefore;
    }

    /**
     * Consider signatures made after the given timestamp invalid.
     *
     * @param timestamp timestamp
     * @return options
     */
    public ConsumerOptions verifyNotAfter(Date timestamp) {
        this.verifyNotAfter = timestamp;
        return this;
    }

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
     * TODO: Implement
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-2.1">RFC4880 on Session Keys</a>
     *
     * @param sessionKey session key
     * @return options
     */
    public ConsumerOptions setSessionKey(@Nonnull byte[] sessionKey) {
        this.sessionKey = sessionKey;
        return this;
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
     * Add a passphrase for message decryption.
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

    public @Nullable SecretKeyRingProtector getSecretKeyProtector(PGPSecretKeyRing decryptionKeyRing) {
        return decryptionKeys.get(decryptionKeyRing);
    }

    public @Nonnull Set<PGPSignature> getDetachedSignatures() {
        return Collections.unmodifiableSet(detachedSignatures);
    }
}
