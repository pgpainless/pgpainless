// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.exception.KeyException;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve;
import org.pgpainless.key.generation.type.xdh_legacy.XDHLegacySpec;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.util.Passphrase;

import javax.annotation.Nonnull;

public class EncryptionOptionsTest {

    private static OpenPGPKey secretKeys;
    private static OpenPGPCertificate publicKeys;
    private static OpenPGPCertificate.OpenPGPComponentKey primaryKey;
    private static OpenPGPCertificate.OpenPGPComponentKey encryptComms;
    private static OpenPGPCertificate.OpenPGPComponentKey encryptStorage;

    @BeforeAll
    public static void generateKey() {
        secretKeys = PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.CERTIFY_OTHER)
                        .build())
                .addSubkey(KeySpec.getBuilder(KeyType.XDH_LEGACY(XDHLegacySpec._X25519), KeyFlag.ENCRYPT_COMMS)
                        .build())
                .addSubkey(KeySpec.getBuilder(KeyType.XDH_LEGACY(XDHLegacySpec._X25519), KeyFlag.ENCRYPT_STORAGE)
                        .build())
                .addUserId("test@pgpainless.org")
                .build();

        publicKeys = secretKeys.toCertificate();

        Iterator<OpenPGPCertificate.OpenPGPComponentKey> iterator = publicKeys.getKeys().iterator();
        primaryKey = iterator.next();
        encryptComms = iterator.next();
        encryptStorage = iterator.next();
    }

    @Test
    public void testOverrideEncryptionAlgorithmFailsForNULL() {
        EncryptionOptions options = EncryptionOptions.get();
        assertNull(options.getEncryptionAlgorithmOverride());

        assertThrows(IllegalArgumentException.class, () -> options.overrideEncryptionAlgorithm(SymmetricKeyAlgorithm.NULL));

        assertNull(options.getEncryptionAlgorithmOverride());
    }

    @Test
    public void testOverrideEncryptionOptions() {
        EncryptionOptions options = EncryptionOptions.get();
        assertNull(options.getEncryptionAlgorithmOverride());
        options.overrideEncryptionAlgorithm(SymmetricKeyAlgorithm.AES_128);

        assertEquals(SymmetricKeyAlgorithm.AES_128, options.getEncryptionAlgorithmOverride());
    }

    @Test
    public void testAddRecipients_EncryptCommunications() {
        EncryptionOptions options = EncryptionOptions.encryptCommunications();
        options.addRecipient(publicKeys);

        Set<OpenPGPCertificate.OpenPGPComponentKey> encryptionKeys = options.getEncryptionKeys();
        assertEquals(1, encryptionKeys.size());
        assertEquals(encryptComms, encryptionKeys.iterator().next());
    }

    @Test
    public void testAddRecipients_EncryptDataAtRest() {
        EncryptionOptions options = EncryptionOptions.encryptDataAtRest();
        options.addRecipient(publicKeys);

        Set<OpenPGPCertificate.OpenPGPComponentKey> encryptionKeys = options.getEncryptionKeys();
        assertEquals(1, encryptionKeys.size());
        assertEquals(encryptStorage, encryptionKeys.iterator().next());
    }

    @Test
    public void testAddRecipients_AllKeys() {
        EncryptionOptions options = EncryptionOptions.get();
        options.addRecipient(publicKeys, EncryptionOptions.encryptToAllCapableSubkeys());

        Set<OpenPGPCertificate.OpenPGPComponentKey> encryptionKeys = options.getEncryptionKeys();

        assertEquals(2, encryptionKeys.size());
        assertTrue(encryptionKeys.contains(encryptComms));
        assertTrue(encryptionKeys.contains(encryptStorage));
    }

    @Test
    public void testAddEmptyRecipientsFails() {
        EncryptionOptions options = EncryptionOptions.get();
        assertThrows(IllegalArgumentException.class, () -> options.addRecipients(Collections.emptyList()));
        assertThrows(IllegalArgumentException.class, () -> options.addRecipients(Collections.emptyList(),
                ArrayList::new));
    }

    @Test
    public void testAddEmptyPassphraseFails() {
        EncryptionOptions options = EncryptionOptions.get();
        assertThrows(IllegalArgumentException.class, () ->
                options.addMessagePassphrase(Passphrase.emptyPassphrase()));
    }

    @Test
    public void testAddRecipient_KeyWithoutEncryptionKeyFails() {
        EncryptionOptions options = EncryptionOptions.get();
        OpenPGPKey secretKeys = PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA))
                .addUserId("test@pgpainless.org")
                .build();
        OpenPGPCertificate publicKeys = secretKeys.toCertificate();

        assertThrows(KeyException.UnacceptableEncryptionKeyException.class, () -> options.addRecipient(publicKeys));
    }

    @Test
    public void testEncryptionKeySelectionStrategyEmpty_ThrowsAssertionError() {
        EncryptionOptions options = EncryptionOptions.get();

        assertThrows(KeyException.UnacceptableEncryptionKeyException.class,
                () -> options.addRecipient(publicKeys, new EncryptionOptions.EncryptionKeySelector() {
                    @NotNull
                    @Override
                    public List<OpenPGPCertificate.OpenPGPComponentKey> selectEncryptionSubkeys(@NotNull List<? extends OpenPGPCertificate.OpenPGPComponentKey> encryptionCapableKeys) {
                        return Collections.emptyList();
                    }
                }));

        assertThrows(KeyException.UnacceptableEncryptionKeyException.class,
                () -> options.addRecipient(publicKeys, "test@pgpainless.org", new EncryptionOptions.EncryptionKeySelector() {
                    @Override
                    public List<OpenPGPCertificate.OpenPGPComponentKey> selectEncryptionSubkeys(@Nonnull List<? extends OpenPGPCertificate.OpenPGPComponentKey> encryptionCapableKeys) {
                        return Collections.emptyList();
                    }
                }));
    }

    @Test
    public void testAddRecipients_PGPPublicKeyRingCollection() {
        PGPPublicKeyRing secondKeyRing = KeyRingUtils.publicKeyRingFrom(
                PGPainless.generateKeyRing().modernKeyRing("other@pgpainless.org")
                        .getPGPSecretKeyRing());

        PGPPublicKeyRingCollection collection = new PGPPublicKeyRingCollection(
                Arrays.asList(publicKeys.getPGPPublicKeyRing(), secondKeyRing));

        EncryptionOptions options = EncryptionOptions.get();
        options.addRecipients(collection, EncryptionOptions.encryptToFirstSubkey());
        assertEquals(2, options.getEncryptionKeyIdentifiers().size());
    }

    @Test
    public void testAddRecipient_withValidUserId() {
        EncryptionOptions options = EncryptionOptions.get();
        options.addRecipient(publicKeys, "test@pgpainless.org", EncryptionOptions.encryptToFirstSubkey());

        assertEquals(1, options.getEncryptionMethods().size());
    }

    @Test
    public void testAddRecipient_withInvalidUserId() {
        EncryptionOptions options = EncryptionOptions.get();
        assertThrows(KeyException.UnboundUserIdException.class, () -> options.addRecipient(publicKeys, "invalid@user.id"));
    }
}
