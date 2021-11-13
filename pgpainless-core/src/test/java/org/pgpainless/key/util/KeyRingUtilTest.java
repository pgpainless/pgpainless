// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.NoSuchElementException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.CollectionUtils;

public class KeyRingUtilTest {

    @Test
    public void testDeleteUserIdFromSecretKeyRing()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Alice", null);

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId("Bob", SecretKeyRingProtector.unprotectedKeys())
                .done();
        assertEquals(2, CollectionUtils.iteratorToList(secretKeys.getPublicKey().getUserIDs()).size());

        secretKeys = KeyRingUtils.deleteUserId(secretKeys, "Bob");

        assertEquals(1, CollectionUtils.iteratorToList(secretKeys.getPublicKey().getUserIDs()).size());
    }

    @Test
    public void testDeleteUserIdFromPublicKeyRing()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Alice", null);

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId("Bob", SecretKeyRingProtector.unprotectedKeys())
                .done();
        PGPPublicKeyRing publicKeys = PGPainless.extractCertificate(secretKeys);
        assertEquals(2, CollectionUtils.iteratorToList(publicKeys.getPublicKey().getUserIDs()).size());

        publicKeys = KeyRingUtils.deleteUserId(publicKeys, "Alice");

        assertEquals(1, CollectionUtils.iteratorToList(publicKeys.getPublicKey().getUserIDs()).size());
    }

    @Test
    public void testDeleteNonexistentUserIdFromKeyRingThrows()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Alice", null);

        assertThrows(NoSuchElementException.class,
                () -> KeyRingUtils.deleteUserId(secretKeys, "Charlie"));
    }
}
