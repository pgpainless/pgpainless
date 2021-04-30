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

import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.key.protection.SecretKeyRingProtector;
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
        return onOutputStream(outputStream, OpenPgpMetadata.FileInfo.binaryStream());
    }
    /**
     * Create a {@link EncryptionStream} on an {@link OutputStream} that contains the plain data which shall
     * be encrypted and/or signed.
     *
     * @param outputStream outputStream
     * @param forYourEyesOnly flag indicating that the data is intended for the recipients eyes only
     * @return api handle
     *
     * @deprecated use {@link #onOutputStream(OutputStream, OpenPgpMetadata.FileInfo)} instead.
     */
    default ToRecipients onOutputStream(@Nonnull OutputStream outputStream, boolean forYourEyesOnly) {
        return onOutputStream(outputStream, forYourEyesOnly ? OpenPgpMetadata.FileInfo.forYourEyesOnly() : OpenPgpMetadata.FileInfo.binaryStream());
    }

    /**
     * Creates a {@link EncryptionStream} on an {@link OutputStream} that contains the plain data which shall
     * be encrypted and/or signed.
     *
     * @param outputStream outputStream
     * @param fileName name of the file (or "" if the encrypted data is not a file)
     * @param forYourEyesOnly flag indicating that the data is intended for the recipients eyes only
     * @return api handle
     *
     * @deprecated use {@link #onOutputStream(OutputStream, OpenPgpMetadata.FileInfo)} instead.
     */
    default ToRecipients onOutputStream(@Nonnull OutputStream outputStream, String fileName, boolean forYourEyesOnly) {
        return onOutputStream(outputStream, new OpenPgpMetadata.FileInfo(forYourEyesOnly ? "_CONSOLE" : fileName, new Date(), StreamEncoding.BINARY));
    }

    /**
     * Create an {@link EncryptionStream} on an {@link OutputStream} that contains the plain data which shall
     * be encrypted and/or signed.
     *
     * @param outputStream outputStream
     * @param fileInfo file information
     * @return api handle
     */
    ToRecipients onOutputStream(@Nonnull OutputStream outputStream, OpenPgpMetadata.FileInfo fileInfo);

    interface ToRecipients {

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
        WithAlgorithms andToSelf(@Nonnull PGPPublicKeyRing... keys);

        /**
         * Add our own public keys to the list of recipient keys.
         *
         * @param keys own public keys
         * @return api handle
         */
        WithAlgorithms andToSelf(@Nonnull PGPPublicKeyRingCollection keys);

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
         * Pass in a list of secret keys used for signing, along with a {@link SecretKeyRingProtector} used to unlock
         * the secret keys.
         *
         * @param decryptor {@link SecretKeyRingProtector} used to unlock the secret keys
         * @param keyRings secret keys used for signing
         * @return api handle
         */
        DocumentType signWith(@Nonnull SecretKeyRingProtector decryptor, @Nonnull PGPSecretKeyRing... keyRings);

        DocumentType signWith(@Nonnull SecretKeyRingProtector decryptor, @Nonnull PGPSecretKeyRingCollection keyRings);

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
