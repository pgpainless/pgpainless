// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>, 2021 Flowcrypt a.s.
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ChangePrimaryUserIdAndExpirationDatesTest {

    private static final long millisInHour = 1000 * 60 * 60;

    @Test
    public void generateA_primaryB_revokeA_cantSecondaryA()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("A");
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        Date now = new Date();
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys, now);
        assertFalse(info.isHardRevoked("A"));
        assertFalse(info.isHardRevoked("B"));
        assertIsPrimaryUserId("A", info);
        assertIsNotValid("B", info);
        assertIsNotPrimaryUserId("B", info);

        // One hour later
        Date oneHourLater = new Date(now.getTime() + millisInHour);
        secretKeys = PGPainless.modifyKeyRing(secretKeys, oneHourLater)
                .addPrimaryUserId("B", protector)
                .done();
        info = PGPainless.inspectKeyRing(secretKeys, oneHourLater);

        assertIsPrimaryUserId("B", info);
        assertIsNotPrimaryUserId("A", info);

        // Two hours later
        Date twoHoursLater = new Date(now.getTime() + 2 * millisInHour);

        secretKeys = PGPainless.modifyKeyRing(secretKeys, twoHoursLater)
                .revokeUserId("A", protector) // hard revoke A
                .done();
        info = PGPainless.inspectKeyRing(secretKeys, twoHoursLater);

        assertTrue(info.isHardRevoked("A"));
        assertFalse(info.isHardRevoked("B"));
        assertIsPrimaryUserId("B", info);
        assertIsNotValid("A", info);

        // Three hours later
        Date threeHoursLater = new Date(now.getTime() + 3 * millisInHour);

        PGPSecretKeyRing finalSecretKeys = secretKeys;
        assertThrows(IllegalArgumentException.class, () ->
                PGPainless.modifyKeyRing(finalSecretKeys, threeHoursLater).addUserId("A", protector));
    }

    @Test
    public void generateA_primaryExpire_isExpired()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("A");
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        assertIsPrimaryUserId("A", info);

        Date now = new Date();
        Date later = new Date(now.getTime() + millisInHour);

        secretKeys = PGPainless.modifyKeyRing(secretKeys, now)
                .setExpirationDate(later, protector) // expire the whole key
                .done();

        Date evenLater = new Date(now.getTime() + 2 * millisInHour);

        info = PGPainless.inspectKeyRing(secretKeys, evenLater);
        assertFalse(info.isUserIdValid("A")); // is expired by now
    }

    @Test
    public void generateA_primaryB_primaryExpire_bIsStillPrimary()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("A");
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        Date now = new Date();
        // Generate key with primary user-id A
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        assertIsPrimaryUserId("A", info);

        // later set primary user-id to B
        Date t1 = new Date(now.getTime() + millisInHour);
        secretKeys = PGPainless.modifyKeyRing(secretKeys, t1)
                .addPrimaryUserId("B", protector)
                .done();
        info = PGPainless.inspectKeyRing(secretKeys, t1);
        assertIsPrimaryUserId("B", info);
        assertIsNotPrimaryUserId("A", info);

        // Even later expire the whole key
        Date t2 = new Date(now.getTime() + 2 * millisInHour);
        Date expiration = new Date(now.getTime() + 10 * millisInHour);
        secretKeys = PGPainless.modifyKeyRing(secretKeys, t2)
                .setExpirationDate(expiration, protector) // expire the whole key in 1 hour
                .done();

        Date t3 = new Date(now.getTime() + 3 * millisInHour);

        info = PGPainless.inspectKeyRing(secretKeys, t3);
        assertIsValid("A", info);
        assertIsValid("B", info);
        assertIsPrimaryUserId("B", info);
        assertIsNotPrimaryUserId("A", info);

        info = PGPainless.inspectKeyRing(secretKeys, expiration);
        assertIsPrimaryUserId("B", info);   // B is still primary, even though
        assertFalse(info.isUserIdValid("A"));      // key is expired by now
        assertFalse(info.isUserIdValid("B"));
    }

    @Test
    public void generateA_expire_certify()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing("A");
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        Date now = new Date();
        Date t1 = new Date(now.getTime() + millisInHour);
        secretKeys = PGPainless.modifyKeyRing(secretKeys, now)
                .setExpirationDate(t1, protector)
                .done();

        Date t2 = new Date(now.getTime() + 2 * millisInHour);
        Date t4 = new Date(now.getTime() + 4 * millisInHour);
        secretKeys = PGPainless.modifyKeyRing(secretKeys, t2)
                .setExpirationDate(t4, protector)
                .done();

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        assertIsValid("A", info);
        assertIsPrimaryUserId("A", info);
    }

    @Test
    public void generateA_expire_primaryB_expire_isPrimaryB()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing("A");
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        Date now = new Date();
        Date t1 = new Date(now.getTime() + millisInHour);
        secretKeys = PGPainless.modifyKeyRing(secretKeys, t1)
                .setExpirationDate(t1, protector)
                .done();

        Date t2 = new Date(now.getTime() + 2 * millisInHour);
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys, t2);

        assertIsPrimaryUserId("A", info);
        assertIsNotValid("A", info); // A is expired

        secretKeys = PGPainless.modifyKeyRing(secretKeys, t2)
                .addPrimaryUserId("B", protector)
                .done();

        Date t3 = new Date(now.getTime() + 3 * millisInHour);
        info = PGPainless.inspectKeyRing(secretKeys, t3);

        assertIsPrimaryUserId("B", info);
        assertIsNotValid("B", info); // A and B are still expired
        assertIsNotValid("A", info);

        Date t4 = new Date(now.getTime() + 4 * millisInHour);
        Date t5 = new Date(now.getTime() + 5 * millisInHour);
        secretKeys = PGPainless.modifyKeyRing(secretKeys, t3)
                .setExpirationDate(t5, protector)
                .done();

        info = PGPainless.inspectKeyRing(secretKeys, t4);
        assertIsValid("B", info);
        assertIsValid("A", info); // A got re-validated when changing exp date
        assertIsPrimaryUserId("B", info);

        secretKeys = PGPainless.modifyKeyRing(secretKeys, t4)
                .addUserId("A", protector) // re-certify A as non-primary user-id
                .done();
        info = PGPainless.inspectKeyRing(secretKeys, t4);

        assertIsValid("B", info);
        assertIsValid("A", info);
        assertIsPrimaryUserId("B", info);

    }

    private static void assertIsPrimaryUserId(String userId, KeyRingInfo info) {
        assertEquals(userId, info.getPrimaryUserId());
    }

    private static void assertIsNotPrimaryUserId(String userId, KeyRingInfo info) {
        PGPSignature signature = info.getLatestUserIdCertification(userId);
        if (signature == null) {
            return;
        }

        assertFalse(signature.getHashedSubPackets().isPrimaryUserID());
    }

    private static void assertIsValid(String userId, KeyRingInfo info) {
        assertTrue(info.isUserIdValid(userId));
    }

    private static void assertIsNotValid(String userId, KeyRingInfo info) {
        assertFalse(info.isUserIdValid(userId));
    }
}
