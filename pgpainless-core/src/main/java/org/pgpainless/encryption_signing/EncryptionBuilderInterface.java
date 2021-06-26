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
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.exception.KeyValidationException;
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
    default ToRecipientsOrNoEncryption onOutputStream(@Nonnull OutputStream outputStream) {
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
    default ToRecipientsOrNoEncryption onOutputStream(@Nonnull OutputStream outputStream, boolean forYourEyesOnly) {
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
    default ToRecipientsOrNoEncryption onOutputStream(@Nonnull OutputStream outputStream, String fileName, boolean forYourEyesOnly) {
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
    ToRecipientsOrNoEncryption onOutputStream(@Nonnull OutputStream outputStream, OpenPgpMetadata.FileInfo fileInfo);

    interface ToRecipientsOrNoEncryption extends ToRecipients {

        /**
         * Create an {@link EncryptionStream} with the given options (recipients, signers, algorithms...).
         *
         * @param options options
         * @return encryption strea
         */
        EncryptionStream withOptions(ProducerOptions options) throws PGPException, IOException;

        /**
         * Instruct the {@link EncryptionStream} to not encrypt any data.
         *
         * @return api handle
         */
        SignWithOrDontSign doNotEncrypt();
    }

    interface ToRecipients {

        /**
         * Encrypt for the given valid public key.
         * With this method, the recipient key is being addressed by key-id,
         * so this method prioritizes algorithm preferences from the keys direct-key signature.
         *
         * @param key recipient key for which the message will be encrypted.
         * @return api handle
         */
        AdditionalRecipients toRecipient(@Nonnull PGPPublicKeyRing key);

        /**
         * Encrypt for the given valid key using the provided user-id signature to determine preferences.
         *
         * @param key public key
         * @param userId user-id which is used to select the correct encryption parameters based on preferences.
         * @return api handle
         */
        AdditionalRecipients toRecipient(@Nonnull PGPPublicKeyRing key, @Nonnull String userId);

        /**
         * Encrypt for the first valid key in the provided keys collection which has a valid user-id that matches
         * the provided userId.
         * The user-id is also used to determine encryption preferences.
         *
         * @param keys collection of keys
         * @param userId user-id used to select the correct key
         * @return api handle
         */
        AdditionalRecipients toRecipient(@Nonnull PGPPublicKeyRingCollection keys, @Nonnull String userId);

        /**
         * Encrypt for all valid public keys in the provided collection.
         * If any key is not eligible for encryption (e.g. expired, revoked...),
         * an {@link IllegalArgumentException} will be thrown.
         *
         * @param keys collection of public keys
         * @return api handle
         */
        AdditionalRecipients toRecipients(@Nonnull PGPPublicKeyRingCollection keys);

        /**
         * Symmetrically encrypt the message using a passphrase.
         * Note that the passphrase MUST NOT be empty.
         *
         * @param passphrase passphrase
         * @return api handle
         */
        AdditionalRecipients forPassphrase(Passphrase passphrase);

    }

    interface AdditionalRecipients {
        /**
         * Add an additional recipient key/passphrase or configure signing.
         *
         * @return api handle
         */
        ToRecipientsOrSign and();
    }

    // Allow additional recipient or signing configuration
    interface ToRecipientsOrSign extends ToRecipients, SignWithOrDontSign {
    }

    // Allow signing configuration or no signing at all
    interface SignWithOrDontSign extends SignWith {
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
         * @deprecated use {@link #signInlineWith(SecretKeyRingProtector, PGPSecretKeyRing)} instead.
         * @param decryptor {@link SecretKeyRingProtector} used to unlock the secret keys
         * @param keyRings secret keys used for signing
         * @return api handle
         */
        @Deprecated
        AdditionalSignWith signWith(@Nonnull SecretKeyRingProtector decryptor, @Nonnull PGPSecretKeyRing... keyRings) throws KeyValidationException, PGPException;

        /**
         * Sign inline using the passed in secret keys.
         *
         * @deprecated use {@link #signInlineWith(SecretKeyRingProtector, PGPSecretKeyRing)} instead.
         * @param decryptor for unlocking the secret keys
         * @param keyRings secret keys
         * @return api handle
         */
        @Deprecated
        AdditionalSignWith signWith(@Nonnull SecretKeyRingProtector decryptor, @Nonnull PGPSecretKeyRingCollection keyRings) throws KeyValidationException, PGPException;

        /**
         * Create an inline signature using the provided secret key.
         * The signature will be of type {@link DocumentSignatureType#BINARY_DOCUMENT}.
         *
         * @param secretKeyDecryptor for unlocking the secret key
         * @param signingKey signing key
         * @return api handle
         */
        default AdditionalSignWith signInlineWith(@Nonnull SecretKeyRingProtector secretKeyDecryptor, @Nonnull PGPSecretKeyRing signingKey) throws PGPException, KeyValidationException {
            return signInlineWith(secretKeyDecryptor, signingKey, null);
        }

        /**
         * Create an inline signature using the provided secret key.
         * If userId is not null, the preferences of the matching user-id on the key will be used for signing.
         * The signature will be of type {@link DocumentSignatureType#BINARY_DOCUMENT}.
         *
         * @param secretKeyDecryptor for unlocking the secret key
         * @param signingKey signing key
         * @param userId userId whose preferences shall be used for signing
         * @return api handle
         */
        default AdditionalSignWith signInlineWith(@Nonnull SecretKeyRingProtector secretKeyDecryptor, @Nonnull PGPSecretKeyRing signingKey, String userId) throws PGPException, KeyValidationException {
            return signInlineWith(secretKeyDecryptor, signingKey, userId, DocumentSignatureType.BINARY_DOCUMENT);
        }

        /**
         * Create an inline signature using the provided secret key with the algorithm preferences of the provided user-id.
         *
         * @param secretKeyDecryptor for unlocking the secret key
         * @param signingKey signing key
         * @param userId user-id whose preferences shall be used for signing
         * @param signatureType signature type
         * @return api handle
         */
        AdditionalSignWith signInlineWith(@Nonnull SecretKeyRingProtector secretKeyDecryptor, @Nonnull PGPSecretKeyRing signingKey, String userId, DocumentSignatureType signatureType) throws KeyValidationException, PGPException;

        /**
         * Create a detached signature using the provided secret key.
         *
         * @param secretKeyDecryptor for unlocking the secret key
         * @param signingKey signing key
         * @return api handle
         */
        default AdditionalSignWith signDetachedWith(@Nonnull SecretKeyRingProtector secretKeyDecryptor, @Nonnull PGPSecretKeyRing signingKey) throws PGPException, KeyValidationException {
            return signDetachedWith(secretKeyDecryptor, signingKey, null);
        }

        /**
         * Create a detached signature using the provided secret key with the algorithm preferences of the provided user-id.
         *
         * @param secretKeyDecryptor for unlocking the secret key
         * @param signingKey signing key
         * @param userId user-id whose preferences shall be used for signing
         * @return api handle
         */
        default AdditionalSignWith signDetachedWith(@Nonnull SecretKeyRingProtector secretKeyDecryptor, @Nonnull PGPSecretKeyRing signingKey, String userId) throws PGPException, KeyValidationException {
            return signDetachedWith(secretKeyDecryptor, signingKey, userId, DocumentSignatureType.BINARY_DOCUMENT);
        }

        /**
         * Create a detached signature using the provided secret key with the algorithm preferences of the provided user-id.
         *
         * @param secretKeyDecryptor for unlocking the secret key
         * @param signingKey signing key
         * @param userId user-id whose preferences shall be used for signing
         * @param signatureType type of the signature
         * @return api handle
         */
        AdditionalSignWith signDetachedWith(@Nonnull SecretKeyRingProtector secretKeyDecryptor, @Nonnull PGPSecretKeyRing signingKey, String userId, DocumentSignatureType signatureType) throws PGPException, KeyValidationException;
    }

    interface AdditionalSignWith extends Armor {
        /**
         * Add an additional signing key/method.
         *
         * @return api handle
         */
        SignWith and();
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
