/*
 * Copyright 2018 Paul Schaub.
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

import javax.annotation.Nonnull;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.util.Passphrase;

public interface DecryptionBuilderInterface {

    /**
     * Create a {@link DecryptionStream} on an {@link InputStream} which contains the encrypted and/or signed data.
     *
     * @param inputStream encrypted and/or signed data.
     * @return api handle
     */
    DecryptWith onInputStream(@Nonnull InputStream inputStream);

    interface DecryptWith {

        /**
         * Add options for decryption / signature verification, such as keys, passphrases etc.
         *
         * @param consumerOptions consumer options
         * @return decryption stream
         * @throws PGPException in case of an OpenPGP related error
         * @throws IOException in case of an IO error
         */
        DecryptionStream withOptions(ConsumerOptions consumerOptions) throws PGPException, IOException;

        /**
         * Decrypt the encrypted data using the secret keys found in the provided {@link PGPSecretKeyRingCollection}.
         * Here it is assumed that the secret keys are not password protected.
         * For password protected secret keys use {@link #decryptWith(SecretKeyRingProtector, PGPSecretKeyRingCollection)}
         * and pass in a {@link org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector}.
         *
         * @param secretKeyRings secret keys
         * @return api handle
         *
         * @deprecated use {@link ConsumerOptions#addDecryptionKey(PGPSecretKeyRing, SecretKeyRingProtector)}
         * ({@link #withOptions(ConsumerOptions)}) instead.
         */
        @Deprecated
        default Verify decryptWith(@Nonnull PGPSecretKeyRingCollection secretKeyRings) {
            return decryptWith(new UnprotectedKeysProtector(), secretKeyRings);
        }

        /**
         * Decrypt the encrypted data using the secret keys found in the provided {@link PGPSecretKeyRingCollection}.
         * The secret keys are being unlocked by the provided {@link SecretKeyRingProtector}.
         *
         * @param decryptor for unlocking locked secret keys
         * @param secretKeyRings secret keys
         * @return api handle
         *
         * @deprecated use {@link ConsumerOptions#addDecryptionKey(PGPSecretKeyRing, SecretKeyRingProtector)}
         * ({@link #withOptions(ConsumerOptions)}) instead.
         */
        @Deprecated
        Verify decryptWith(@Nonnull SecretKeyRingProtector decryptor, @Nonnull PGPSecretKeyRingCollection secretKeyRings);

        /**
         * Decrypt the encrypted data using the provided {@link PGPSecretKeyRing}.
         * The secret key is unlocked by the provided {@link SecretKeyRingProtector}.
         *
         * @param decryptor for unlocking locked secret key
         * @param secretKeyRing secret key
         * @return api handle
         *
         * @deprecated use {@link ConsumerOptions#addDecryptionKey(PGPSecretKeyRing, SecretKeyRingProtector)}
         * ({@link #withOptions(ConsumerOptions)}) instead.
         */
        @Deprecated
        Verify decryptWith(@Nonnull SecretKeyRingProtector decryptor, @Nonnull PGPSecretKeyRing secretKeyRing)
                throws PGPException, IOException;

        /**
         * Decrypt the encrypted data using a passphrase.
         * Note: The passphrase MUST NOT be empty.
         *
         * @param passphrase passphrase
         * @return api handle
         *
         * @deprecated use {@link ConsumerOptions#addDecryptionPassphrase(Passphrase)}
         * ({@link #withOptions(ConsumerOptions)}) instead.
         */
        @Deprecated
        Verify decryptWith(@Nonnull Passphrase passphrase);

        /**
         * Do not attempt to decrypt the provided data.
         * Useful for signature verification of signed-only data.
         *
         * @return api handle
         *
         * @deprecated use {@link #withOptions(ConsumerOptions)} instead and set no decryption keys.
         */
        @Deprecated
        Verify doNotDecrypt();

    }

    @Deprecated
    interface Verify extends VerifyWith {

        @Override
        @Deprecated
        HandleMissingPublicKeys verifyWith(@Nonnull PGPPublicKeyRingCollection publicKeyRings);

        @Override
        @Deprecated
        default HandleMissingPublicKeys verifyWith(@Nonnull OpenPgpV4Fingerprint trustedFingerprint,
                                                   @Nonnull PGPPublicKeyRingCollection publicKeyRings) {
            return verifyWith(Collections.singleton(trustedFingerprint), publicKeyRings);
        }

        @Override
        @Deprecated
        HandleMissingPublicKeys verifyWith(@Nonnull Set<OpenPgpV4Fingerprint> trustedFingerprints,
                                           @Nonnull PGPPublicKeyRingCollection publicKeyRings);

        @Override
        @Deprecated
        default HandleMissingPublicKeys verifyWith(@Nonnull PGPPublicKeyRing publicKeyRing) {
            return verifyWith(Collections.singleton(publicKeyRing));
        }

        @Override
        @Deprecated
        HandleMissingPublicKeys verifyWith(@Nonnull Set<PGPPublicKeyRing> publicKeyRings);

        /**
         * Pass in one or more detached signatures to verify.
         *
         * @param bytes detached signatures (ascii armored or binary).
         * @return api handle
         * @throws IOException if some IO error occurs
         * @throws PGPException if the detached signatures are malformed
         *
         * @deprecated use {@link ConsumerOptions#addVerificationOfDetachedSignature(PGPSignature)}
         * ({@link DecryptWith#withOptions(ConsumerOptions)}) instead.
         */
        @Deprecated
        default VerifyWith verifyDetachedSignature(@Nonnull byte[] bytes) throws IOException, PGPException {
            return verifyDetachedSignature(new ByteArrayInputStream(bytes));
        }

        /**
         * Pass in one or more detached signatures to verify.
         *
         * @param inputStream detached signature (ascii armored or binary).
         * @return api handle
         * @throws IOException in case something is wrong with the input stream
         * @throws PGPException if the detached signatures are malformed
         *
         * @deprecated use {@link ConsumerOptions#addVerificationOfDetachedSignature(PGPSignature)}
         * ({@link DecryptWith#withOptions(ConsumerOptions)}) instead.
         */
        @Deprecated
        VerifyWith verifyDetachedSignature(@Nonnull InputStream inputStream) throws IOException, PGPException;

        /**
         * Pass in a detached signature to verify.
         *
         * @param signature detached signature
         * @return api handle
         *
         * @deprecated use {@link ConsumerOptions#addVerificationOfDetachedSignature(PGPSignature)}
         * ({@link DecryptWith#withOptions(ConsumerOptions)}) instead.
         */
        @Deprecated
        default VerifyWith verifyDetachedSignature(@Nonnull PGPSignature signature) {
            return verifyDetachedSignatures(Collections.singletonList(signature));
        }

        /**
         * Pass in a list of detached signatures to verify.
         *
         * @param signatures detached signatures
         * @return api handle
         *
         * @deprecated use {@link ConsumerOptions#addVerificationOfDetachedSignature(PGPSignature)}
         * ({@link DecryptWith#withOptions(ConsumerOptions)}) instead.
         */
        @Deprecated
        VerifyWith verifyDetachedSignatures(@Nonnull List<PGPSignature> signatures);

        /**
         * Instruct the {@link DecryptionStream} to not verify any signatures.
         *
         * @return api handle
         *
         * @deprecated use {@link DecryptWith#withOptions(ConsumerOptions)} instead and don't set verification keys.
         */
        @Deprecated
        Build doNotVerify();
    }

    @Deprecated
    interface VerifyWith {

        /**
         * Pass in a collection of public keys to verify the signatures with.
         *
         * @param publicKeyRings public keys
         * @return api handle
         *
         * @deprecated use {@link ConsumerOptions#addVerificationCerts(PGPPublicKeyRingCollection)}
         * ({@link DecryptWith#withOptions(ConsumerOptions)}) instead.
         */
        @Deprecated
        HandleMissingPublicKeys verifyWith(@Nonnull PGPPublicKeyRingCollection publicKeyRings);

        /**
         * Pass in a collection of public keys along with the fingerprint of the key that shall be used to
         * verify the signatures.
         *
         * @param trustedFingerprint {@link OpenPgpV4Fingerprint} of the public key that shall be used to verify the signatures.
         * @param publicKeyRings public keys
         * @return api handle
         * @deprecated use {@link ConsumerOptions#addVerificationCert(PGPPublicKeyRing)}
          * ({@link DecryptWith#withOptions(ConsumerOptions)}) instead.
         */
        @Deprecated
        default HandleMissingPublicKeys verifyWith(@Nonnull OpenPgpV4Fingerprint trustedFingerprint,
                                                   @Nonnull PGPPublicKeyRingCollection publicKeyRings) {
            return verifyWith(Collections.singleton(trustedFingerprint), publicKeyRings);
        }

        /**
         * Pass in a collection of public keys along with a set of fingerprints of those keys that shall be used to
         * verify the signatures.
         *
         * @param trustedFingerprints set of trusted {@link OpenPgpV4Fingerprint OpenPgpV4Fingerprints}.
         * @param publicKeyRings public keys
         * @return api handle
         *
         * @deprecated use {@link ConsumerOptions#addVerificationCert(PGPPublicKeyRing)}
         * ({@link DecryptWith#withOptions(ConsumerOptions)}) instead.
         */
        @Deprecated
        HandleMissingPublicKeys verifyWith(@Nonnull Set<OpenPgpV4Fingerprint> trustedFingerprints,
                                           @Nonnull PGPPublicKeyRingCollection publicKeyRings);

        /**
         * Pass in a trusted public key ring to verify the signature with.
         *
         * @param publicKeyRing public key
         * @return api handle
         *
         * @deprecated use {@link ConsumerOptions#addVerificationCert(PGPPublicKeyRing)}
         * ({@link DecryptWith#withOptions(ConsumerOptions)}) instead.
         */
        @Deprecated
        default HandleMissingPublicKeys verifyWith(@Nonnull PGPPublicKeyRing publicKeyRing) {
            return verifyWith(Collections.singleton(publicKeyRing));
        }

        /**
         * Pass in a set of trusted public keys to verify the signatures with.
         *
         * @param publicKeyRings public keys
         * @return api handle
         *
         * @deprecated use {@link ConsumerOptions#addVerificationCert(PGPPublicKeyRing)}
         * ({@link DecryptWith#withOptions(ConsumerOptions)}) instead.
         */
        @Deprecated
        HandleMissingPublicKeys verifyWith(@Nonnull Set<PGPPublicKeyRing> publicKeyRings);

    }

    @Deprecated
    interface HandleMissingPublicKeys {

        /**
         * Pass in a callback that can is used to request missing public keys.
         *
         * @param callback callback
         * @return api handle
         *
         * @deprecated use {@link ConsumerOptions#setMissingCertificateCallback(MissingPublicKeyCallback)}
         * ({@link DecryptWith#withOptions(ConsumerOptions)}) instead.
         */
        @Deprecated
        Build handleMissingPublicKeysWith(@Nonnull MissingPublicKeyCallback callback);

        /**
         * Instruct the {@link DecryptionStream} to ignore any missing public keys.
         *
         * @return api handle
         *
         * @deprecated simply do not set a {@link MissingPublicKeyCallback} and use
         * {@link DecryptWith#withOptions(ConsumerOptions)} instead.
         */
        @Deprecated
        Build ignoreMissingPublicKeys();
    }

    @Deprecated
    interface Build {

        /**
         * Build the configured {@link DecryptionStream}.
         *
         * @return the decryption stream
         * @throws IOException in case of an I/O error
         * @throws PGPException if something is malformed
         * @throws org.pgpainless.exception.UnacceptableAlgorithmException if the message uses weak/unacceptable algorithms
         *
         * @deprecated use {@link DecryptWith#withOptions(ConsumerOptions)} instead.
         */
        @Deprecated
        DecryptionStream build() throws IOException, PGPException;

    }

}
