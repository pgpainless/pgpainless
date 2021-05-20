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
package org.pgpainless.encryption_signing;

import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.util.Passphrase;

public class EncryptionOptions {

    private final EncryptionStream.Purpose purpose;
    private final Set<PGPKeyEncryptionMethodGenerator> encryptionMethods = new LinkedHashSet<>();
    private final Set<SubkeyIdentifier> encryptionKeys = new LinkedHashSet<>();
    private final Map<SubkeyIdentifier, KeyRingInfo> keyRingInfo = new HashMap<>();

    private SymmetricKeyAlgorithm encryptionAlgorithmOverride = null;

    public EncryptionOptions() {
        this(EncryptionStream.Purpose.STORAGE_AND_COMMUNICATIONS);
    }

    public EncryptionOptions(EncryptionStream.Purpose purpose) {
        this.purpose = purpose;
    }

    public static EncryptionOptions encryptCommunications() {
        return new EncryptionOptions(EncryptionStream.Purpose.COMMUNICATIONS);
    }

    public static EncryptionOptions encryptDataAtRest() {
        return new EncryptionOptions(EncryptionStream.Purpose.STORAGE);
    }

    /**
     * Add a recipient by providing a key and recipient user-id.
     * The user-id is used to determine the recipients preferences (algorithms etc.).
     *
     * @param key key ring
     * @param userId user id
     */
    public void addRecipient(PGPPublicKeyRing key, String userId) {
        KeyRingInfo info = new KeyRingInfo(key, new Date());

        PGPPublicKey encryptionSubkey = info.getEncryptionSubkey(userId, purpose);
        if (encryptionSubkey == null) {
            throw new AssertionError("Key has no encryption subkey.");
        }
        addRecipientKey(key, encryptionSubkey);
    }

    /**
     * Add a recipient by providing a key.
     *
     * @param key key ring
     */
    public void addRecipient(PGPPublicKeyRing key) {
        KeyRingInfo info = new KeyRingInfo(key, new Date());
        PGPPublicKey encryptionSubkey = info.getEncryptionSubkey(purpose);
        if (encryptionSubkey == null) {
            throw new IllegalArgumentException("Key has no encryption subkey.");
        }
        addRecipientKey(key, encryptionSubkey);
    }

    private void addRecipientKey(PGPPublicKeyRing keyRing, PGPPublicKey key) {
        encryptionKeys.add(new SubkeyIdentifier(keyRing, key.getKeyID()));
        PGPKeyEncryptionMethodGenerator encryptionMethod = ImplementationFactory
                .getInstance().getPublicKeyKeyEncryptionMethodGenerator(key);
        addEncryptionMethod(encryptionMethod);
    }

    /**
     * Add a symmetric passphrase which the message will be encrypted to.
     *
     * @param passphrase passphrase
     */
    public void addPassphrase(Passphrase passphrase) {
        if (passphrase.isEmpty()) {
            throw new IllegalArgumentException("Passphrase must not be empty.");
        }
        PBEKeyEncryptionMethodGenerator encryptionMethod = ImplementationFactory
                .getInstance().getPBEKeyEncryptionMethodGenerator(passphrase);
        addEncryptionMethod(encryptionMethod);
    }

    /**
     * Add an {@link PGPKeyEncryptionMethodGenerator} which will be used to encrypt the message.
     * Method generators are either {@link PBEKeyEncryptionMethodGenerator} (passphrase)
     * or {@link PGPKeyEncryptionMethodGenerator} (public key).
     *
     * This method is intended for advanced users to allow encryption for specific subkeys.
     * This can come in handy for example if data needs to be encrypted to a subkey that's ignored by PGPainless.
     *
     * @param encryptionMethod encryption method
     */
    public void addEncryptionMethod(PGPKeyEncryptionMethodGenerator encryptionMethod) {
        encryptionMethods.add(encryptionMethod);
    }

    public Set<PGPKeyEncryptionMethodGenerator> getEncryptionMethods() {
        return new HashSet<>(encryptionMethods);
    }

    public Set<SubkeyIdentifier> getEncryptionKeyIdentifiers() {
        return new HashSet<>(encryptionKeys);
    }

    public SymmetricKeyAlgorithm getEncryptionAlgorithmOverride() {
        return encryptionAlgorithmOverride;
    }

    public void overrideEncryptionAlgorithm(SymmetricKeyAlgorithm encryptionAlgorithm) {
        if (encryptionAlgorithm == SymmetricKeyAlgorithm.NULL) {
            throw new IllegalArgumentException("Plaintext encryption can only be used to denote unencrypted secret keys.");
        }
        this.encryptionAlgorithmOverride = encryptionAlgorithm;
    }
}
