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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.exception.KeyValidationError;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.xdh.XDHSpec;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.util.Passphrase;

public class EncryptionOptionsTest {

    private static PGPSecretKeyRing secretKeys;
    private static PGPPublicKeyRing publicKeys;
    private static SubkeyIdentifier primaryKey;
    private static SubkeyIdentifier encryptComms;
    private static SubkeyIdentifier encryptStorage;

    @BeforeAll
    public static void generateKey() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        secretKeys = PGPainless.generateKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.CERTIFY_OTHER)
                        .build())
                .addSubkey(KeySpec.getBuilder(KeyType.XDH(XDHSpec._X25519), KeyFlag.ENCRYPT_COMMS)
                        .build())
                .addSubkey(KeySpec.getBuilder(KeyType.XDH(XDHSpec._X25519), KeyFlag.ENCRYPT_STORAGE)
                        .build())
                .addUserId("test@pgpainless.org")
                .build();

        publicKeys = KeyRingUtils.publicKeyRingFrom(secretKeys);

        Iterator<PGPPublicKey> iterator = publicKeys.iterator();
        primaryKey = new SubkeyIdentifier(publicKeys, iterator.next().getKeyID());
        encryptComms = new SubkeyIdentifier(publicKeys, iterator.next().getKeyID());
        encryptStorage = new SubkeyIdentifier(publicKeys, iterator.next().getKeyID());
    }

    @Test
    public void testOverrideEncryptionAlgorithmFailsForNULL() {
        EncryptionOptions options = new EncryptionOptions();
        assertNull(options.getEncryptionAlgorithmOverride());

        assertThrows(IllegalArgumentException.class, () -> options.overrideEncryptionAlgorithm(SymmetricKeyAlgorithm.NULL));

        assertNull(options.getEncryptionAlgorithmOverride());
    }

    @Test
    public void testOverrideEncryptionOptions() {
        EncryptionOptions options = new EncryptionOptions();
        assertNull(options.getEncryptionAlgorithmOverride());
        options.overrideEncryptionAlgorithm(SymmetricKeyAlgorithm.AES_128);

        assertEquals(SymmetricKeyAlgorithm.AES_128, options.getEncryptionAlgorithmOverride());
    }

    @Test
    public void testAddRecipients_EncryptCommunications() {
        EncryptionOptions options = EncryptionOptions.encryptCommunications();
        options.addRecipient(publicKeys);

        Set<SubkeyIdentifier> encryptionKeys = options.getEncryptionKeyIdentifiers();
        assertEquals(1, encryptionKeys.size());
        assertEquals(encryptComms, encryptionKeys.iterator().next());
    }

    @Test
    public void testAddRecipients_EncryptDataAtRest() {
        EncryptionOptions options = EncryptionOptions.encryptDataAtRest();
        options.addRecipient(publicKeys);

        Set<SubkeyIdentifier> encryptionKeys = options.getEncryptionKeyIdentifiers();
        assertEquals(1, encryptionKeys.size());
        assertEquals(encryptStorage, encryptionKeys.iterator().next());
    }

    @Test
    public void testAddRecipients_AllKeys() {
        EncryptionOptions options = new EncryptionOptions();
        options.addRecipient(publicKeys, EncryptionOptions.encryptToAllCapableSubkeys());

        Set<SubkeyIdentifier> encryptionKeys = options.getEncryptionKeyIdentifiers();

        assertEquals(2, encryptionKeys.size());
        assertTrue(encryptionKeys.contains(encryptComms));
        assertTrue(encryptionKeys.contains(encryptStorage));
    }

    @Test
    public void testAddEmptyPassphraseFails() {
        EncryptionOptions options = new EncryptionOptions();
        assertThrows(IllegalArgumentException.class, () ->
                options.addPassphrase(Passphrase.emptyPassphrase()));
    }

    @Test
    public void testAddRecipient_KeyWithoutEncryptionKeyFails() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        EncryptionOptions options = new EncryptionOptions();
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA))
                .addUserId("test@pgpainless.org")
                .build();
        PGPPublicKeyRing publicKeys = KeyRingUtils.publicKeyRingFrom(secretKeys);

        assertThrows(IllegalArgumentException.class, () -> options.addRecipient(publicKeys));
    }

    @Test
    public void testEncryptionKeySelectionStrategyEmpty_ThrowsAssertionError() {
        EncryptionOptions options = new EncryptionOptions();

        assertThrows(IllegalArgumentException.class,
                () -> options.addRecipient(publicKeys, new EncryptionOptions.EncryptionKeySelector() {
                    @Override
                    public List<PGPPublicKey> selectEncryptionSubkeys(List<PGPPublicKey> encryptionCapableKeys) {
                        return Collections.emptyList();
                    }
                }));

        assertThrows(IllegalArgumentException.class,
                () -> options.addRecipient(publicKeys, "test@pgpainless.org", new EncryptionOptions.EncryptionKeySelector() {
                    @Override
                    public List<PGPPublicKey> selectEncryptionSubkeys(List<PGPPublicKey> encryptionCapableKeys) {
                        return Collections.emptyList();
                    }
                }));
    }

    @Test
    public void testAddRecipients_PGPPublicKeyRingCollection() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPPublicKeyRing secondKeyRing = KeyRingUtils.publicKeyRingFrom(
                PGPainless.generateKeyRing().modernKeyRing("other@pgpainless.org", null));

        PGPPublicKeyRingCollection collection = new PGPPublicKeyRingCollection(
                Arrays.asList(publicKeys, secondKeyRing));

        EncryptionOptions options = new EncryptionOptions();
        options.addRecipients(collection, EncryptionOptions.encryptToFirstSubkey());
        assertEquals(2, options.getEncryptionKeyIdentifiers().size());
    }

    @Test
    public void testAddRecipient_withValidUserId() {
        EncryptionOptions options = new EncryptionOptions();
        options.addRecipient(publicKeys, "test@pgpainless.org", EncryptionOptions.encryptToFirstSubkey());

        assertEquals(1, options.getEncryptionMethods().size());
    }

    @Test
    public void testAddRecipient_withInvalidUserId() {
        EncryptionOptions options = new EncryptionOptions();
        assertThrows(KeyValidationError.class, () -> options.addRecipient(publicKeys, "invalid@user.id"));
    }
}
