// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.selection.userid.SelectUserId;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RevokeUserIdsTest {

    @Test
    public void revokeWithSelectUserId() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Alice <alice@pgpainless.org>", null);
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId("Allice <alice@example.org>", protector)
                .addUserId("Alice <alice@example.org>", protector)
                .done();

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        assertTrue(info.isUserIdValid("Alice <alice@pgpainless.org>"));
        assertTrue(info.isUserIdValid("Allice <alice@example.org>"));
        assertTrue(info.isUserIdValid("Alice <alice@example.org>"));

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .revokeUserIds(SelectUserId.containsEmailAddress("alice@example.org"), protector, null)
                .done();

        info = PGPainless.inspectKeyRing(secretKeys);
        assertTrue(info.isUserIdValid("Alice <alice@pgpainless.org>"));
        assertFalse(info.isUserIdValid("Allice <alice@example.org>"));
        assertFalse(info.isUserIdValid("Alice <alice@example.org>"));
    }

    @Test
    public void emptySelectionYieldsNoSuchElementException() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Alice <alice@pgpainless.org>", null);

        assertThrows(NoSuchElementException.class, () ->
                PGPainless.modifyKeyRing(secretKeys).revokeUserIds(
                        SelectUserId.containsEmailAddress("alice@example.org"),
                        SecretKeyRingProtector.unprotectedKeys(),
                        null));
    }
}
