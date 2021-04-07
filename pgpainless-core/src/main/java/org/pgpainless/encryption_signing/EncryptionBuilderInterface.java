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
package org.pgpainless.encryption_signing;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.exception.SecretKeyNotFoundException;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.util.selection.keyring.PublicKeyRingSelectionStrategy;
import org.pgpainless.util.selection.keyring.SecretKeyRingSelectionStrategy;
import org.pgpainless.util.MultiMap;
import org.pgpainless.util.Passphrase;

public interface EncryptionBuilderInterface {

    /**
     * Create a {@link EncryptionStream} on an {@link OutputStream} that contains the plain data that
     * shall be encrypted and or signed.
     *
     * @param outputStream output stream of the plain data.
     * @return api handle
     */
    default ToRecipients onOutputStream(@Nonnull OutputStream outputStream) {
        return onOutputStream(outputStream,false);
    }
    /**
     * Create a {@link EncryptionStream} on an {@link OutputStream} that contains the plain data which shall
     * be encrypted and/or signed.
     *
     * @param outputStream outputStream
     * @param forYourEyesOnly flag indicating that the data is intended for the recipients eyes only
     * @return api handle
     */
    default ToRecipients onOutputStream(@Nonnull OutputStream outputStream, boolean forYourEyesOnly) {
        return onOutputStream(outputStream, "", forYourEyesOnly);
    }

    /**
     * Creates a {@link EncryptionStream} on an {@link OutputStream} that contains the plain data which shall
     * be encrypted and/or signed.
     *
     * @param outputStream outputStream
     * @param fileName name of the file (or "" if the encrypted data is not a file)
     * @param forYourEyesOnly flag indicating that the data is intended for the recipients eyes only
     * @return api handle
     */
    ToRecipients onOutputStream(@Nonnull OutputStream outputStream, String fileName, boolean forYourEyesOnly);

    interface ToRecipients {

        /**
         * Pass in a list of trusted public keys of the recipients.
         *
         * @param keys recipient keys for which the message will be encrypted.
         * @return api handle
         */
        WithAlgorithms toRecipients(@Nonnull PGPPublicKey... keys);

        /**
         * Pass in a list of trusted public key rings of the recipients.
         *
         * @param keys recipient keys for which the message will be encrypted.
         * @return api handle
         */
        WithAlgorithms toRecipients(@Nonnull PGPPublicKeyRing... keys);

        /**
         * Pass in a list of trusted public key ring collections of the recipients.
         *
         * @param keys recipient keys for which the message will be encrypted.
         * @return api handle
         */
        WithAlgorithms toRecipients(@Nonnull PGPPublicKeyRingCollection... keys);

        /**
         * Pass in a map of recipient key ring collections along with a strategy for key selection.
         *
         * @param selectionStrategy selection strategy that is used to select suitable encryption keys.
         * @param keys public keys
         * @param <O> selection criteria type (eg. email address) on which the selection strategy is based
         * @return api handle
         */
        <O> WithAlgorithms toRecipients(@Nonnull PublicKeyRingSelectionStrategy<O> selectionStrategy,
                                       @Nonnull MultiMap<O, PGPPublicKeyRingCollection> keys);

        /**
         * Encrypt to one or more symmetric passphrases.
         * Note that the passphrases MUST NOT be empty.
         *
         * @param passphrases passphrase
         * @return api handle
         */
        WithAlgorithms forPassphrases(Passphrase... passphrases);

        /**
         * Instruct the {@link EncryptionStream} to not encrypt any data.
         *
         * @return api handle
         */
        DetachedSign doNotEncrypt();

    }

    interface WithAlgorithms {

        /**
         * Add our own public key to the list of recipient keys.
         *
         * @param keys own public keys
         * @return api handle
         */
        WithAlgorithms andToSelf(@Nonnull PGPPublicKey... keys);

        /**
         * Add our own public key to the list of recipient keys.
         *
         * @param keys own public keys
         * @return api handle
         */
        WithAlgorithms andToSelf(@Nonnull PGPPublicKeyRing... keys);

        /**
         * Add our own public keys to the list of recipient keys.
         *
         * @param keys own public keys
         * @return api handle
         */
        WithAlgorithms andToSelf(@Nonnull PGPPublicKeyRingCollection keys);

        /**
         * Add our own public keys to the list of recipient keys.
         *
         * @param selectionStrategy key selection strategy used to determine suitable keys for encryption.
         * @param keys public keys
         * @param <O> selection criteria type (eg. email address) used by the selection strategy.
         * @return api handle
         */
        <O> WithAlgorithms andToSelf(@Nonnull PublicKeyRingSelectionStrategy<O> selectionStrategy,
                                    @Nonnull MultiMap<O, PGPPublicKeyRingCollection> keys);

        /**
         * Specify which algorithms should be used for the encryption.
         *
         * @param symmetricKeyAlgorithm symmetric algorithm for the session key
         * @param hashAlgorithm hash algorithm
         * @param compressionAlgorithm compression algorithm
         * @return api handle
         */
        DetachedSign usingAlgorithms(@Nonnull SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                                 @Nonnull HashAlgorithm hashAlgorithm,
                                 @Nonnull CompressionAlgorithm compressionAlgorithm);

        /**
         * Use a suite of algorithms that are considered secure.
         *
         * @return api handle
         */
        DetachedSign usingSecureAlgorithms();

        ToRecipients and();

    }

    interface DetachedSign extends SignWith {

        /**
         * Instruct the {@link EncryptionStream} to generate detached signatures instead of One-Pass-Signatures.
         * Those can be retrieved later via {@link OpenPgpMetadata#getSignatures()}.
         *
         * @return api handle
         */
        SignWith createDetachedSignature();

        /**
         * Do not sign the plain data at all.
         *
         * @return api handle
         */
        Armor doNotSign();

    }

    interface SignWith {

        /**
         * Pass in a list of secret keys used for signing.
         * Those keys are considered unlocked (ie. not password protected).
         * If you need to use password protected keys instead, use {@link #signWith(SecretKeyRingProtector, PGPSecretKey...)}.
         *
         * @param keys secret keys
         * @return api handle
         */
        default DocumentType signWith(@Nonnull PGPSecretKey... keys) {
            return signWith(new UnprotectedKeysProtector(), keys);
        }

        /**
         * Pass in a list of secret keys used for signing, along with a {@link SecretKeyRingProtector} used to unlock
         * the secret keys.
         *
         * @param decryptor {@link SecretKeyRingProtector} used to unlock the secret keys
         * @param keys secret keys used for signing
         * @return api handle
         */
        DocumentType signWith(@Nonnull SecretKeyRingProtector decryptor, @Nonnull PGPSecretKey... keys);

        /**
         * Pass in a list of secret keys used for signing, along with a {@link SecretKeyRingProtector} used to unlock
         * the secret keys.
         *
         * @param decryptor {@link SecretKeyRingProtector} used to unlock the secret keys
         * @param keyRings secret keys used for signing
         * @return api handle
         */
        DocumentType signWith(@Nonnull SecretKeyRingProtector decryptor, @Nonnull PGPSecretKeyRing... keyRings);

        /**
         * Pass in a map of secret keys for signing, as well as a {@link org.pgpainless.util.selection.key.SecretKeySelectionStrategy}
         * that is used to determine suitable secret keys.
         * If the keys are locked by a password, the provided {@link SecretKeyRingProtector} will be used to unlock the keys.
         *
         * @param selectionStrategy key selection strategy
         * @param decryptor decryptor for unlocking secret keys
         * @param keys secret keys
         * @param <O> selection criteria type (eg. email address)
         * @return api handle
         *
         * @throws SecretKeyNotFoundException in case no suitable secret key can be found
         */
        <O> DocumentType signWith(@Nonnull SecretKeyRingSelectionStrategy<O> selectionStrategy,
                          @Nonnull SecretKeyRingProtector decryptor,
                          @Nonnull MultiMap<O, PGPSecretKeyRingCollection> keys)
                throws SecretKeyNotFoundException;

    }

    interface DocumentType {

        Armor signBinaryDocument();

        Armor signCanonicalText();
    }

    interface Armor {

        /**
         * Wrap the encrypted/signed output in an ASCII armor.
         * This can come in handy for sending the encrypted message via eg. email.
         *
         * @return encryption stream
         * @throws IOException in case some I/O error occurs
         * @throws PGPException in case of some malformed pgp data
         */
        EncryptionStream asciiArmor() throws IOException, PGPException;

        /**
         * Do not wrap the output in an ASCII armor.
         *
         * @return encryption stream
         * @throws IOException in case some I/O error occurs
         * @throws PGPException in case of some malformed pgp data
         */
        EncryptionStream noArmor() throws IOException, PGPException;

    }

}
