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
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.key.KeyRingValidator;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.Tuple;
import org.pgpainless.util.selection.key.PublicKeySelectionStrategy;
import org.pgpainless.util.selection.key.SecretKeySelectionStrategy;
import org.pgpainless.util.selection.key.impl.And;
import org.pgpainless.util.selection.key.impl.EncryptionKeySelectionStrategy;
import org.pgpainless.util.selection.key.impl.NoRevocation;
import org.pgpainless.util.selection.key.impl.SignatureKeySelectionStrategy;

public class EncryptionBuilder implements EncryptionBuilderInterface {

    private final EncryptionStream.Purpose purpose;
    private OutputStream outputStream;
    private final Map<SubkeyIdentifier, PGPPublicKeyRing> encryptionKeys = new ConcurrentHashMap<>();
    private final Set<Passphrase> encryptionPassphrases = new HashSet<>();
    private boolean detachedSignature = false;
    private SignatureType signatureType = SignatureType.BINARY_DOCUMENT;
    private final Map<SubkeyIdentifier, PGPSecretKeyRing> signingKeys = new ConcurrentHashMap<>();
    private SecretKeyRingProtector signingKeysDecryptor;
    private SymmetricKeyAlgorithm symmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES_128;
    private HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;
    private CompressionAlgorithm compressionAlgorithm = CompressionAlgorithm.UNCOMPRESSED;
    private boolean asciiArmor = false;
    private OpenPgpMetadata.FileInfo fileInfo;

    public EncryptionBuilder() {
        this.purpose = EncryptionStream.Purpose.COMMUNICATIONS;
    }

    public EncryptionBuilder(@Nonnull EncryptionStream.Purpose purpose) {
        this.purpose = purpose;
    }

    @Override
    public ToRecipients onOutputStream(@Nonnull OutputStream outputStream, OpenPgpMetadata.FileInfo fileInfo) {
        this.outputStream = outputStream;
        this.fileInfo = fileInfo;
        return new ToRecipientsImpl();
    }

    class ToRecipientsImpl implements ToRecipients {

        @Override
        public WithAlgorithms toRecipients(@Nonnull PGPPublicKeyRing... keys) {
            if (keys.length == 0) {
                throw new IllegalArgumentException("No public keys provided.");
            }

            Map<SubkeyIdentifier, PGPPublicKeyRing> encryptionKeys = new ConcurrentHashMap<>();
            for (PGPPublicKeyRing ring : keys) {
                PGPPublicKeyRing validatedKeyRing = KeyRingValidator.validate(ring, PGPainless.getPolicy());
                for (PGPPublicKey k : validatedKeyRing) {
                    if (encryptionKeySelector().accept(k)) {
                        encryptionKeys.put(new SubkeyIdentifier(ring, k.getKeyID()), ring);
                    }
                }
            }
            if (encryptionKeys.isEmpty()) {
                throw new IllegalArgumentException("No valid encryption keys found!");
            }
            EncryptionBuilder.this.encryptionKeys.putAll(encryptionKeys);

            return new WithAlgorithmsImpl();
        }

        private String getPrimaryUserId(PGPPublicKey publicKey) {
            // TODO: Use real function to get primary userId.
            return publicKey.getUserIDs().next();
        }

        @Override
        public WithAlgorithms toRecipients(@Nonnull PGPPublicKeyRingCollection... keys) {
            if (keys.length == 0) {
                throw new IllegalArgumentException("No key ring collections provided.");
            }

            for (PGPPublicKeyRingCollection collection : keys) {
                for (PGPPublicKeyRing ring : collection) {
                    Map<SubkeyIdentifier, PGPPublicKeyRing> encryptionKeys = new ConcurrentHashMap<>();
                    for (PGPPublicKey k : ring) {
                        if (encryptionKeySelector().accept(k)) {
                            encryptionKeys.put(new SubkeyIdentifier(ring, k.getKeyID()), ring);
                        }
                    }

                    if (encryptionKeys.isEmpty()) {
                        throw new IllegalArgumentException("No valid encryption keys found!");
                    }

                    EncryptionBuilder.this.encryptionKeys.putAll(encryptionKeys);
                }
            }

            return new WithAlgorithmsImpl();
        }

        @Override
        public WithAlgorithms forPassphrases(Passphrase... passphrases) {
            List<Passphrase> passphraseList = new ArrayList<>();
            for (Passphrase passphrase : passphrases) {
                if (passphrase.isEmpty()) {
                    throw new IllegalArgumentException("Passphrase must not be empty.");
                }
                passphraseList.add(passphrase);
            }
            EncryptionBuilder.this.encryptionPassphrases.addAll(passphraseList);
            return new WithAlgorithmsImpl();
        }

        @Override
        public DetachedSign doNotEncrypt() {
            return new DetachedSignImpl();
        }
    }

    class WithAlgorithmsImpl implements WithAlgorithms {

        @Override
        public WithAlgorithms andToSelf(@Nonnull PGPPublicKeyRing... keys) {
            if (keys.length == 0) {
                throw new IllegalArgumentException("Recipient list MUST NOT be empty.");
            }
            for (PGPPublicKeyRing ring : keys) {
                Map<SubkeyIdentifier, PGPPublicKeyRing> encryptionKeys = new ConcurrentHashMap<>();
                for (Iterator<PGPPublicKey> i = ring.getPublicKeys(); i.hasNext(); ) {
                    PGPPublicKey key = i.next();
                    if (encryptionKeySelector().accept(key)) {
                        encryptionKeys.put(new SubkeyIdentifier(ring, key.getKeyID()), ring);
                    }
                }
                if (encryptionKeys.isEmpty()) {
                    throw new IllegalArgumentException("No suitable encryption key found in the key ring " + new OpenPgpV4Fingerprint(ring));
                }
                EncryptionBuilder.this.encryptionKeys.putAll(encryptionKeys);
            }
            return this;
        }

        @Override
        public WithAlgorithms andToSelf(@Nonnull PGPPublicKeyRingCollection keys) {
            for (PGPPublicKeyRing ring : keys) {
                Map<SubkeyIdentifier, PGPPublicKeyRing> encryptionKeys = new ConcurrentHashMap<>();
                for (Iterator<PGPPublicKey> i = ring.getPublicKeys(); i.hasNext(); ) {
                    PGPPublicKey key = i.next();
                    if (encryptionKeySelector().accept(key)) {
                        encryptionKeys.put(new SubkeyIdentifier(ring, key.getKeyID()), ring);
                    }
                }
                if (encryptionKeys.isEmpty()) {
                    throw new IllegalArgumentException("No suitable encryption key found in the key ring " + new OpenPgpV4Fingerprint(ring));
                }
                EncryptionBuilder.this.encryptionKeys.putAll(encryptionKeys);
            }
            return this;
        }

        @Override
        public DetachedSign usingAlgorithms(@Nonnull SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                                            @Nonnull HashAlgorithm hashAlgorithm,
                                            @Nonnull CompressionAlgorithm compressionAlgorithm) {

            EncryptionBuilder.this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
            EncryptionBuilder.this.hashAlgorithm = hashAlgorithm;
            EncryptionBuilder.this.compressionAlgorithm = compressionAlgorithm;

            return new DetachedSignImpl();
        }

        @Override
        public DetachedSign usingSecureAlgorithms() {
            EncryptionBuilder.this.symmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES_256;
            EncryptionBuilder.this.hashAlgorithm = HashAlgorithm.SHA512;
            EncryptionBuilder.this.compressionAlgorithm = CompressionAlgorithm.UNCOMPRESSED;

            return new DetachedSignImpl();
        }

        @Override
        public ToRecipients and() {
            return new ToRecipientsImpl();
        }
    }

    class DetachedSignImpl implements DetachedSign {

        @Override
        public SignWith createDetachedSignature() {
            EncryptionBuilder.this.detachedSignature = true;
            return new SignWithImpl();
        }

        @Override
        public Armor doNotSign() {
            return new ArmorImpl();
        }

        @Override
        public DocumentType signWith(@Nonnull SecretKeyRingProtector decryptor, @Nonnull PGPSecretKeyRing... keyRings) {
            return new SignWithImpl().signWith(decryptor, keyRings);
        }

        @Override
        public DocumentType signWith(@Nonnull SecretKeyRingProtector decryptor, @Nonnull PGPSecretKeyRingCollection keyRings) {
            return new SignWithImpl().signWith(decryptor, keyRings);
        }

    }

    class SignWithImpl implements SignWith {

        @Override
        public DocumentType signWith(@Nonnull SecretKeyRingProtector decryptor,
                                     @Nonnull PGPSecretKeyRing... keyRings) {
            if (keyRings.length == 0) {
                throw new IllegalArgumentException("Signing key list MUST NOT be empty.");
            }
            for (PGPSecretKeyRing ring : keyRings) {
                Map<SubkeyIdentifier, PGPSecretKeyRing> signingKeys = new ConcurrentHashMap<>();
                for (Iterator<PGPSecretKey> i = ring.getSecretKeys(); i.hasNext(); ) {
                    PGPSecretKey s = i.next();
                    if (EncryptionBuilder.this.signingKeySelector().accept(s)) {
                        signingKeys.put(new SubkeyIdentifier(ring, s.getKeyID()), ring);
                    }
                }

                if (signingKeys.isEmpty()) {
                    throw new IllegalArgumentException("No suitable signing key found in the key ring " + new OpenPgpV4Fingerprint(ring));
                }

                EncryptionBuilder.this.signingKeys.putAll(signingKeys);
            }
            EncryptionBuilder.this.signingKeysDecryptor = decryptor;
            return new DocumentTypeImpl();
        }

        @Override
        public DocumentType signWith(@Nonnull SecretKeyRingProtector decryptor, @Nonnull PGPSecretKeyRingCollection keyRings) {
            Iterator<PGPSecretKeyRing> iterator = keyRings.iterator();
            if (!iterator.hasNext()) {
                throw new IllegalArgumentException("Signing key collection MUST NOT be empty.");
            }
            while (iterator.hasNext()) {
                PGPSecretKeyRing ring = iterator.next();
                Map<SubkeyIdentifier, PGPSecretKeyRing> signingKeys = new ConcurrentHashMap<>();
                for (Iterator<PGPSecretKey> i = ring.getSecretKeys(); i.hasNext(); ) {
                    PGPSecretKey s = i.next();
                    if (EncryptionBuilder.this.signingKeySelector().accept(s)) {
                        signingKeys.put(new SubkeyIdentifier(ring, s.getKeyID()), ring);
                    }
                }

                if (signingKeys.isEmpty()) {
                    throw new IllegalArgumentException("No suitable signing key found in the key ring " + new OpenPgpV4Fingerprint(ring));
                }

                EncryptionBuilder.this.signingKeys.putAll(signingKeys);
            }

            EncryptionBuilder.this.signingKeysDecryptor = decryptor;
            return new DocumentTypeImpl();
        }
    }

    class DocumentTypeImpl implements DocumentType {

        @Override
        public Armor signBinaryDocument() {
            EncryptionBuilder.this.signatureType = SignatureType.BINARY_DOCUMENT;
            return new ArmorImpl();
        }

        @Override
        public Armor signCanonicalText() {
            EncryptionBuilder.this.signatureType = SignatureType.CANONICAL_TEXT_DOCUMENT;
            return new ArmorImpl();
        }
    }

    class ArmorImpl implements Armor {

        @Override
        public EncryptionStream asciiArmor() throws IOException, PGPException {
            EncryptionBuilder.this.asciiArmor = true;
            return build();
        }

        @Override
        public EncryptionStream noArmor() throws IOException, PGPException {
            EncryptionBuilder.this.asciiArmor = false;
            return build();
        }

        private EncryptionStream build() throws IOException, PGPException {

            Map<SubkeyIdentifier, Tuple<PGPSecretKeyRing, PGPPrivateKey>> privateKeys = new ConcurrentHashMap<>();
            for (SubkeyIdentifier signingKey : signingKeys.keySet()) {
                PGPSecretKeyRing secretKeyRing = signingKeys.get(signingKey);
                PGPSecretKey secretKey = secretKeyRing.getSecretKey(signingKey.getSubkeyFingerprint().getKeyId());
                PBESecretKeyDecryptor decryptor = signingKeysDecryptor.getDecryptor(secretKey.getKeyID());
                PGPPrivateKey privateKey = secretKey.extractPrivateKey(decryptor);
                privateKeys.put(signingKey, new Tuple<>(secretKeyRing, privateKey));
            }

            return new EncryptionStream(
                    EncryptionBuilder.this.outputStream,
                    EncryptionBuilder.this.encryptionKeys,
                    EncryptionBuilder.this.encryptionPassphrases,
                    EncryptionBuilder.this.detachedSignature,
                    signatureType,
                    privateKeys,
                    EncryptionBuilder.this.symmetricKeyAlgorithm,
                    EncryptionBuilder.this.hashAlgorithm,
                    EncryptionBuilder.this.compressionAlgorithm,
                    EncryptionBuilder.this.asciiArmor,
                    fileInfo);
        }
    }

    PublicKeySelectionStrategy encryptionKeySelector() {
        KeyFlag[] flags = mapPurposeToKeyFlags(purpose);
        return new And.PubKeySelectionStrategy(
                new NoRevocation.PubKeySelectionStrategy(),
                new EncryptionKeySelectionStrategy(flags));
    }

    SecretKeySelectionStrategy signingKeySelector() {
        return new And.SecKeySelectionStrategy(
                new NoRevocation.SecKeySelectionStrategy(),
                new SignatureKeySelectionStrategy());
    }

    private static KeyFlag[] mapPurposeToKeyFlags(EncryptionStream.Purpose purpose) {
        KeyFlag[] flags;
        switch (purpose) {
            case COMMUNICATIONS:
                flags = new KeyFlag[] {KeyFlag.ENCRYPT_COMMS};
                break;
            case STORAGE:
                flags = new KeyFlag[] {KeyFlag.ENCRYPT_STORAGE};
                break;
            case STORAGE_AND_COMMUNICATIONS:
                flags = new KeyFlag[] {KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE};
                break;
            default:
                throw new AssertionError("Illegal purpose enum value encountered.");
        }
        return flags;
    }
}
