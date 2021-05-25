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
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.algorithm.negotiation.SymmetricKeyAlgorithmNegotiator;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.exception.KeyValidationException;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;

public class EncryptionBuilder implements EncryptionBuilderInterface {

    private OutputStream outputStream;
    private EncryptionOptions encryptionOptions;
    private SigningOptions signingOptions = new SigningOptions();
    private ProducerOptions options;
    private OpenPgpMetadata.FileInfo fileInfo;

    public EncryptionBuilder() {
        this.encryptionOptions = new EncryptionOptions(EncryptionStream.Purpose.COMMUNICATIONS);
    }

    public EncryptionBuilder(@Nonnull EncryptionStream.Purpose purpose) {
        this.encryptionOptions = new EncryptionOptions(purpose);
    }

    @Override
    public ToRecipientsOrNoEncryption onOutputStream(@Nonnull OutputStream outputStream, OpenPgpMetadata.FileInfo fileInfo) {
        this.outputStream = outputStream;
        this.fileInfo = fileInfo;
        return new ToRecipientsOrNoEncryptionImpl();
    }

    class ToRecipientsImpl implements ToRecipients {

        @Override
        public AdditionalRecipients toRecipient(@Nonnull PGPPublicKeyRing key) {
            encryptionOptions.addRecipient(key);
            return new AdditionalRecipientsImpl();
        }

        @Override
        public AdditionalRecipients toRecipient(@Nonnull PGPPublicKeyRing key, @Nonnull String userId) {
            encryptionOptions.addRecipient(key, userId);
            return new AdditionalRecipientsImpl();
        }

        @Override
        public AdditionalRecipients toRecipient(@Nonnull PGPPublicKeyRingCollection keys, @Nonnull String userId) {
            for (PGPPublicKeyRing ring : keys) {
                encryptionOptions.addRecipient(ring, userId);
            }
            return new AdditionalRecipientsImpl();
        }

        @Override
        public AdditionalRecipients toRecipients(@Nonnull PGPPublicKeyRingCollection keys) {
            for (PGPPublicKeyRing ring : keys) {
                encryptionOptions.addRecipient(ring);
            }
            return new AdditionalRecipientsImpl();
        }

        @Override
        public AdditionalRecipients forPassphrase(Passphrase passphrase) {
            encryptionOptions.addPassphrase(passphrase);
            return new AdditionalRecipientsImpl();
        }
    }

    class ToRecipientsOrNoEncryptionImpl extends ToRecipientsImpl implements ToRecipientsOrNoEncryption {

        @Override
        public EncryptionStream withOptions(ProducerOptions options) throws PGPException, IOException {
            if (options == null) {
                throw new NullPointerException("ProducerOptions cannot be null.");
            }
            return new EncryptionStream(outputStream, options, fileInfo);
        }

        @Override
        public SignWithOrDontSign doNotEncrypt() {
            EncryptionBuilder.this.encryptionOptions = null;
            return new SignWithOrDontSignImpl();
        }
    }

    class AdditionalRecipientsImpl implements AdditionalRecipients {
        @Override
        public ToRecipientsOrSign and() {
            return new ToRecipientsOrSignImpl();
        }
    }

    class ToRecipientsOrSignImpl extends ToRecipientsImpl implements ToRecipientsOrSign {

        @Override
        public Armor doNotSign() {
            EncryptionBuilder.this.signingOptions = null;
            return new ArmorImpl();
        }

        @Override
        public AdditionalSignWith signWith(@Nonnull SecretKeyRingProtector decryptor, @Nonnull PGPSecretKeyRing... keyRings) throws KeyValidationException, PGPException {
            return new SignWithImpl().signWith(decryptor, keyRings);
        }

        @Override
        public AdditionalSignWith signWith(@Nonnull SecretKeyRingProtector decryptor, @Nonnull PGPSecretKeyRingCollection keyRings) throws PGPException {
            return new SignWithImpl().signWith(decryptor, keyRings);
        }

        @Override
        public AdditionalSignWith signInlineWith(@Nonnull SecretKeyRingProtector secretKeyDecryptor, @Nonnull PGPSecretKeyRing signingKey, String userId, DocumentSignatureType signatureType) throws PGPException {
            return new SignWithImpl().signInlineWith(secretKeyDecryptor, signingKey, userId, signatureType);
        }

        @Override
        public AdditionalSignWith signDetachedWith(@Nonnull SecretKeyRingProtector secretKeyDecryptor, @Nonnull PGPSecretKeyRing signingKey, String userId, DocumentSignatureType signatureType) throws PGPException {
            return new SignWithImpl().signDetachedWith(secretKeyDecryptor, signingKey, userId, signatureType);
        }
    }

    class SignWithOrDontSignImpl extends SignWithImpl implements SignWithOrDontSign {

        @Override
        public Armor doNotSign() {
            return new ArmorImpl();
        }
    }

    class SignWithImpl implements SignWith {

        @Override
        public AdditionalSignWith signWith(@Nonnull SecretKeyRingProtector decryptor,
                                           @Nonnull PGPSecretKeyRing... keyRings)
                throws KeyValidationException, PGPException {
            for (PGPSecretKeyRing secretKeyRing : keyRings) {
                signingOptions.addInlineSignature(decryptor, secretKeyRing, DocumentSignatureType.BINARY_DOCUMENT);
            }
            return new AdditionalSignWithImpl();
        }

        @Override
        public AdditionalSignWith signWith(@Nonnull SecretKeyRingProtector decryptor, @Nonnull PGPSecretKeyRingCollection keyRings)
                throws KeyValidationException, PGPException {
            for (PGPSecretKeyRing key : keyRings) {
                signingOptions.addInlineSignature(decryptor, key, DocumentSignatureType.BINARY_DOCUMENT);
            }
            return new AdditionalSignWithImpl();
        }

        @Override
        public AdditionalSignWith signInlineWith(@Nonnull SecretKeyRingProtector secretKeyDecryptor,
                                                 @Nonnull PGPSecretKeyRing signingKey,
                                                 String userId,
                                                 DocumentSignatureType signatureType)
                throws KeyValidationException, PGPException {
            signingOptions.addInlineSignature(secretKeyDecryptor, signingKey, userId, signatureType);
            return new AdditionalSignWithImpl();
        }

        @Override
        public AdditionalSignWith signDetachedWith(@Nonnull SecretKeyRingProtector secretKeyDecryptor,
                                                   @Nonnull PGPSecretKeyRing signingKey,
                                                   String userId,
                                                   DocumentSignatureType signatureType)
                throws PGPException, KeyValidationException {
            signingOptions.addDetachedSignature(secretKeyDecryptor, signingKey, userId, signatureType);
            return new AdditionalSignWithImpl();
        }
    }

    class AdditionalSignWithImpl implements AdditionalSignWith {

        @Override
        public SignWith and() {
            return new SignWithImpl();
        }

        @Override
        public EncryptionStream asciiArmor() throws IOException, PGPException {
            return new ArmorImpl().asciiArmor();
        }

        @Override
        public EncryptionStream noArmor() throws IOException, PGPException {
            return new ArmorImpl().noArmor();
        }
    }

    class ArmorImpl implements Armor {

        @Override
        public EncryptionStream asciiArmor() throws IOException, PGPException {
            assignProducerOptions();
            options.setAsciiArmor(true);
            return build();
        }

        @Override
        public EncryptionStream noArmor() throws IOException, PGPException {
            assignProducerOptions();
            options.setAsciiArmor(false);
            return build();
        }

        private EncryptionStream build() throws IOException, PGPException {
            return new EncryptionStream(
                    EncryptionBuilder.this.outputStream,
                    EncryptionBuilder.this.options,
                    fileInfo);
        }

        private void assignProducerOptions() {
            if (encryptionOptions != null && signingOptions != null) {
                options = ProducerOptions.signAndEncrypt(encryptionOptions, signingOptions);
            } else if (encryptionOptions != null) {
                options = ProducerOptions.encrypt(encryptionOptions);
            } else if (signingOptions != null) {
                options = ProducerOptions.sign(signingOptions);
            } else {
                options = ProducerOptions.noEncryptionNoSigning();
            }
        }
    }

    /**
     * Negotiate the {@link SymmetricKeyAlgorithm} used for message encryption.
     *
     * @param encryptionOptions encryption options
     * @return negotiated symmetric key algorithm
     */
    public static SymmetricKeyAlgorithm negotiateSymmetricEncryptionAlgorithm(EncryptionOptions encryptionOptions) {
        List<Set<SymmetricKeyAlgorithm>> preferences = new ArrayList<>();
        for (SubkeyIdentifier key : encryptionOptions.getKeyViews().keySet()) {
            preferences.add(encryptionOptions.getKeyViews().get(key).getPreferredSymmetricKeyAlgorithms());
        }

        return SymmetricKeyAlgorithmNegotiator
                .byPopularity()
                .negotiate(
                        PGPainless.getPolicy().getSymmetricKeyEncryptionAlgorithmPolicy(),
                        encryptionOptions.getEncryptionAlgorithmOverride(),
                        preferences);
    }

    public static CompressionAlgorithm negotiateCompressionAlgorithm(ProducerOptions producerOptions) {
        CompressionAlgorithm compressionAlgorithmOverride = producerOptions.getCompressionAlgorithmOverride();
        if (compressionAlgorithmOverride != null) {
            return compressionAlgorithmOverride;
        }

        // TODO: Negotiation

        return PGPainless.getPolicy().getCompressionAlgorithmPolicy().defaultCompressionAlgorithm();
    }
}
