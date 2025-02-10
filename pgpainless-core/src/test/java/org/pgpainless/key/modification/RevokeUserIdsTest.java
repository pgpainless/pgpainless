// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;
import java.util.NoSuchElementException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.util.selection.userid.SelectUserId;

public class RevokeUserIdsTest {

    @Test
    public void revokeWithSelectUserId() throws PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Alice <alice@pgpainless.org>")
                .getPGPSecretKeyRing();
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId("Allice <alice@example.org>", protector)
                .addUserId("Alice <alice@example.org>", protector)
                .done();

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        assertTrue(info.isUserIdValid("Alice <alice@pgpainless.org>"));
        assertTrue(info.isUserIdValid("Allice <alice@example.org>"));
        assertTrue(info.isUserIdValid("Alice <alice@example.org>"));

        Date n1 = new Date(info.getCreationDate().getTime() + 1000); // 1 sec later

        secretKeys = PGPainless.modifyKeyRing(secretKeys, n1)
                .revokeUserIds(
                        SelectUserId.containsEmailAddress("alice@example.org"),
                        protector,
                        RevocationAttributes.createCertificateRevocation()
                                .withReason(RevocationAttributes.Reason.USER_ID_NO_LONGER_VALID)
                                .withoutDescription())
                .done();

        info = PGPainless.inspectKeyRing(secretKeys, n1);
        assertTrue(info.isUserIdValid("Alice <alice@pgpainless.org>"));
        assertFalse(info.isUserIdValid("Allice <alice@example.org>"));
        assertFalse(info.isUserIdValid("Alice <alice@example.org>"));
    }

    @Test
    public void removeUserId() throws PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Alice <alice@pgpainless.org>")
                .getPGPSecretKeyRing();
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId("Allice <alice@example.org>", protector)
                .addUserId("Alice <alice@example.org>", protector)
                .done();

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        assertTrue(info.isUserIdValid("Alice <alice@pgpainless.org>"));
        assertTrue(info.isUserIdValid("Allice <alice@example.org>"));
        assertTrue(info.isUserIdValid("Alice <alice@example.org>"));

        Date n1 = new Date(info.getCreationDate().getTime() + 1000);

        secretKeys = PGPainless.modifyKeyRing(secretKeys, n1)
                .removeUserId("Allice <alice@example.org>", protector)
                .done();

        info = PGPainless.inspectKeyRing(secretKeys, n1);
        assertTrue(info.isUserIdValid("Alice <alice@pgpainless.org>"));
        assertFalse(info.isUserIdValid("Allice <alice@example.org>"));
        assertTrue(info.isUserIdValid("Alice <alice@example.org>"));

        PGPSignature revocation = info.getUserIdRevocation("Allice <alice@example.org>");
        assertNotNull(revocation);

        assertFalse(RevocationAttributes.Reason.isHardRevocation(
                revocation.getHashedSubPackets().getRevocationReason().getRevocationReason()));
    }

    @Test
    public void emptySelectionYieldsNoSuchElementException() {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Alice <alice@pgpainless.org>")
                .getPGPSecretKeyRing();

        assertThrows(NoSuchElementException.class, () ->
                PGPainless.modifyKeyRing(secretKeys).revokeUserIds(
                        SelectUserId.containsEmailAddress("alice@example.org"),
                        SecretKeyRingProtector.unprotectedKeys(),
                        (RevocationAttributes) null));
    }
}
