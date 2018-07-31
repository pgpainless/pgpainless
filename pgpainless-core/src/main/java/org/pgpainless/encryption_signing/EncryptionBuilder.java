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
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.selection.key.PublicKeySelectionStrategy;
import org.pgpainless.key.selection.key.SecretKeySelectionStrategy;
import org.pgpainless.key.selection.key.impl.And;
import org.pgpainless.key.selection.key.impl.EncryptionKeySelectionStrategy;
import org.pgpainless.key.selection.key.impl.NoRevocation;
import org.pgpainless.key.selection.key.impl.SignatureKeySelectionStrategy;
import org.pgpainless.key.selection.keyring.PublicKeyRingSelectionStrategy;
import org.pgpainless.key.selection.keyring.SecretKeyRingSelectionStrategy;
import org.pgpainless.util.MultiMap;

public class EncryptionBuilder implements EncryptionBuilderInterface {

    private OutputStream outputStream;
    private final Set<PGPPublicKey> encryptionKeys = new HashSet<>();
    private final Set<PGPSecretKey> signingKeys = new HashSet<>();
    private SecretKeyRingProtector signingKeysDecryptor;
    private SymmetricKeyAlgorithm symmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES_128;
    private HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;
    private CompressionAlgorithm compressionAlgorithm = CompressionAlgorithm.UNCOMPRESSED;
    private boolean asciiArmor = false;

    @Override
    public ToRecipients onOutputStream(@Nonnull OutputStream outputStream) {
        this.outputStream = outputStream;
        return new ToRecipientsImpl();
    }

    class ToRecipientsImpl implements ToRecipients {

        @Override
        public WithAlgorithms toRecipients(@Nonnull PGPPublicKey... keys) {
            for (PGPPublicKey k : keys) {
                if (encryptionKeySelector().accept(null, k)) {
                    EncryptionBuilder.this.encryptionKeys.add(k);
                } else {
                    throw new IllegalArgumentException("Key " + k.getKeyID() + " is not a valid encryption key.");
                }
            }

            if (EncryptionBuilder.this.encryptionKeys.isEmpty()) {
                throw new IllegalStateException("No valid encryption keys found!");
            }

            return new WithAlgorithmsImpl();
        }

        @Override
        public WithAlgorithms toRecipients(@Nonnull PGPPublicKeyRing... keys) {
            for (PGPPublicKeyRing ring : keys) {
                for (PGPPublicKey k : ring) {
                    if (encryptionKeySelector().accept(null, k)) {
                        EncryptionBuilder.this.encryptionKeys.add(k);
                    }
                }
            }

            if (EncryptionBuilder.this.encryptionKeys.isEmpty()) {
                throw new IllegalStateException("No valid encryption keys found!");
            }

            return new WithAlgorithmsImpl();
        }

        @Override
        public WithAlgorithms toRecipients(@Nonnull PGPPublicKeyRingCollection... keys) {
            for (PGPPublicKeyRingCollection collection : keys) {
                for (PGPPublicKeyRing ring : collection) {
                    for (PGPPublicKey k : ring) {
                        if (encryptionKeySelector().accept(null, k)) {
                            EncryptionBuilder.this.encryptionKeys.add(k);
                        }
                    }
                }
            }

            if (EncryptionBuilder.this.encryptionKeys.isEmpty()) {
                throw new IllegalStateException("No valid encryption keys found!");
            }

            return new WithAlgorithmsImpl();
        }

        @Override
        public <O> WithAlgorithms toRecipients(@Nonnull PublicKeyRingSelectionStrategy<O> ringSelectionStrategy,
                                               @Nonnull MultiMap<O, PGPPublicKeyRingCollection> keys) {
            if (keys.isEmpty()) {
                throw new IllegalArgumentException("Recipient map MUST NOT be empty.");
            }
            MultiMap<O, PGPPublicKeyRing> acceptedKeyRings = ringSelectionStrategy.selectKeyRingsFromCollections(keys);
            for (O identifier : acceptedKeyRings.keySet()) {
                Set<PGPPublicKeyRing> acceptedSet = acceptedKeyRings.get(identifier);
                for (PGPPublicKeyRing ring : acceptedSet) {
                    for (PGPPublicKey k : ring) {
                        if (encryptionKeySelector().accept(null, k)) {
                            EncryptionBuilder.this.encryptionKeys.add(k);
                        }
                    }
                }
            }

            if (EncryptionBuilder.this.encryptionKeys.isEmpty()) {
                throw new IllegalStateException("No valid encryption keys found!");
            }

            return new WithAlgorithmsImpl();
        }

        @Override
        public SignWith doNotEncrypt() {
            return new SignWithImpl();
        }
    }

    class WithAlgorithmsImpl implements WithAlgorithms {

        @Override
        public WithAlgorithms andToSelf(@Nonnull PGPPublicKey... keys) {
            if (keys.length == 0) {
                throw new IllegalArgumentException("Recipient list MUST NOT be empty.");
            }
            for (PGPPublicKey k : keys) {
                if (encryptionKeySelector().accept(null, k)) {
                    EncryptionBuilder.this.encryptionKeys.add(k);
                } else {
                    throw new IllegalArgumentException("Key " + k.getKeyID() + " is not a valid encryption key.");
                }
            }
            return this;
        }

        @Override
        public WithAlgorithms andToSelf(@Nonnull PGPPublicKeyRing... keys) {
            if (keys.length == 0) {
                throw new IllegalArgumentException("Recipient list MUST NOT be empty.");
            }
            for (PGPPublicKeyRing ring : keys) {
                for (Iterator<PGPPublicKey> i = ring.getPublicKeys(); i.hasNext(); ) {
                    PGPPublicKey key = i.next();
                    if (encryptionKeySelector().accept(null, key)) {
                        EncryptionBuilder.this.encryptionKeys.add(key);
                    }
                }
            }
            return this;
        }

        @Override
        public WithAlgorithms andToSelf(@Nonnull PGPPublicKeyRingCollection keys) {
            for (PGPPublicKeyRing ring : keys) {
                for (Iterator<PGPPublicKey> i = ring.getPublicKeys(); i.hasNext(); ) {
                    PGPPublicKey key = i.next();
                    if (encryptionKeySelector().accept(null, key)) {
                        EncryptionBuilder.this.encryptionKeys.add(key);
                    }
                }
            }
            return this;
        }

        public <O> WithAlgorithms andToSelf(@Nonnull PublicKeyRingSelectionStrategy<O> ringSelectionStrategy,
                                            @Nonnull MultiMap<O, PGPPublicKeyRingCollection> keys) {
            if (keys.isEmpty()) {
                throw new IllegalArgumentException("Recipient list MUST NOT be empty.");
            }
            MultiMap<O, PGPPublicKeyRing> acceptedKeyRings =
                    ringSelectionStrategy.selectKeyRingsFromCollections(keys);
            for (O identifier : acceptedKeyRings.keySet()) {
                Set<PGPPublicKeyRing> acceptedSet = acceptedKeyRings.get(identifier);
                for (PGPPublicKeyRing k : acceptedSet) {
                    for (Iterator<PGPPublicKey> i = k.getPublicKeys(); i.hasNext(); ) {
                        PGPPublicKey key = i.next();
                        if (encryptionKeySelector().accept(null, key)) {
                            EncryptionBuilder.this.encryptionKeys.add(key);
                        }
                    }
                }
            }
            return this;
        }

        @Override
        public SignWith usingAlgorithms(@Nonnull SymmetricKeyAlgorithm symmetricKeyAlgorithm,
                                        @Nonnull HashAlgorithm hashAlgorithm,
                                        @Nonnull CompressionAlgorithm compressionAlgorithm) {

            EncryptionBuilder.this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
            EncryptionBuilder.this.hashAlgorithm = hashAlgorithm;
            EncryptionBuilder.this.compressionAlgorithm = compressionAlgorithm;

            return new SignWithImpl();
        }

        @Override
        public SignWith usingSecureAlgorithms() {
            EncryptionBuilder.this.symmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES_256;
            EncryptionBuilder.this.hashAlgorithm = HashAlgorithm.SHA512;
            EncryptionBuilder.this.compressionAlgorithm = CompressionAlgorithm.UNCOMPRESSED;

            return new SignWithImpl();
        }
    }

    class SignWithImpl implements SignWith {

        @Override
        public <O> Armor signWith(@Nonnull SecretKeyRingProtector decryptor,
                                  @Nonnull PGPSecretKey... keys) {
            if (keys.length == 0) {
                throw new IllegalArgumentException("Recipient list MUST NOT be empty.");
            }
            for (PGPSecretKey s : keys) {
                if (EncryptionBuilder.this.<O>signingKeySelector().accept(null, s)) {
                    signingKeys.add(s);
                } else {
                    throw new IllegalArgumentException("Key " + s.getKeyID() + " is not a valid signing key.");
                }
            }
            EncryptionBuilder.this.signingKeysDecryptor = decryptor;
            return new ArmorImpl();
        }

        @Override
        public <O> Armor signWith(@Nonnull SecretKeyRingProtector decryptor,
                                  @Nonnull PGPSecretKeyRing... keys) {
            if (keys.length == 0) {
                throw new IllegalArgumentException("Recipient list MUST NOT be empty.");
            }
            for (PGPSecretKeyRing key : keys) {
                for (Iterator<PGPSecretKey> i = key.getSecretKeys(); i.hasNext(); ) {
                    PGPSecretKey s = i.next();
                    if (EncryptionBuilder.this.<O>signingKeySelector().accept(null, s)) {
                        EncryptionBuilder.this.signingKeys.add(s);
                    }
                }
            }
            EncryptionBuilder.this.signingKeysDecryptor = decryptor;
            return new ArmorImpl();
        }

        @Override
        public <O> Armor signWith(@Nonnull SecretKeyRingSelectionStrategy<O> ringSelectionStrategy,
                                  @Nonnull SecretKeyRingProtector decryptor,
                                  @Nonnull MultiMap<O, PGPSecretKeyRingCollection> keys) {
            if (keys.isEmpty()) {
                throw new IllegalArgumentException("Recipient list MUST NOT be empty.");
            }
            MultiMap<O, PGPSecretKeyRing> acceptedKeyRings =
                    ringSelectionStrategy.selectKeyRingsFromCollections(keys);
            for (O identifier : acceptedKeyRings.keySet()) {
                Set<PGPSecretKeyRing> acceptedSet = acceptedKeyRings.get(identifier);
                for (PGPSecretKeyRing k : acceptedSet) {
                    for (Iterator<PGPSecretKey> i = k.getSecretKeys(); i.hasNext(); ) {
                        PGPSecretKey s = i.next();
                        if (EncryptionBuilder.this.<O>signingKeySelector().accept(null, s)) {
                            EncryptionBuilder.this.signingKeys.add(s);
                        }
                    }
                }
            }
            return new ArmorImpl();
        }

        @Override
        public Armor doNotSign() {
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

            Set<PGPPrivateKey> privateKeys = new HashSet<>();
            for (PGPSecretKey secretKey : signingKeys) {
                privateKeys.add(secretKey.extractPrivateKey(signingKeysDecryptor.getDecryptor(secretKey.getKeyID())));
            }

            return new EncryptionStream(
                    EncryptionBuilder.this.outputStream,
                    EncryptionBuilder.this.encryptionKeys,
                    privateKeys,
                    EncryptionBuilder.this.symmetricKeyAlgorithm,
                    EncryptionBuilder.this.hashAlgorithm,
                    EncryptionBuilder.this.compressionAlgorithm,
                    EncryptionBuilder.this.asciiArmor);
        }
    }

    <O> PublicKeySelectionStrategy<O> encryptionKeySelector() {
        return new And.PubKeySelectionStrategy<>(
                new NoRevocation.PubKeySelectionStrategy<>(),
                new EncryptionKeySelectionStrategy<>());
    }

    <O> SecretKeySelectionStrategy<O> signingKeySelector() {
        return new And.SecKeySelectionStrategy<>(
                new NoRevocation.SecKeySelectionStrategy<>(),
                new SignatureKeySelectionStrategy<>());
    }
}
