// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>, 2021 Flowcrypt a.s.
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.OpenPGPKeyVersion;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.DateUtil;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ChangePrimaryUserIdAndExpirationDatesTest {

    private static final long millisInHour = 1000 * 60 * 60;

    @Test
    public void generateA_primaryB_revokeA_cantSecondaryA()
            throws PGPException {
        PGPainless api = PGPainless.getInstance();

        OpenPGPKey secretKeys = api.generateKey()
                .modernKeyRing("A");
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        Date now = DateUtil.now();
        KeyRingInfo info = api.inspect(secretKeys, now);
        assertFalse(info.isHardRevoked("A"));
        assertFalse(info.isHardRevoked("B"));
        assertIsPrimaryUserId("A", info);
        assertIsNotValid("B", info);
        assertIsNotPrimaryUserId("B", info);

        // One hour later
        Date oneHourLater = new Date(now.getTime() + millisInHour);
        secretKeys = api.modify(secretKeys, oneHourLater)
                .addPrimaryUserId("B", protector)
                .done();
        info = api.inspect(secretKeys, oneHourLater);

        assertIsPrimaryUserId("B", info);
        assertIsNotPrimaryUserId("A", info);

        // Two hours later
        Date twoHoursLater = new Date(now.getTime() + 2 * millisInHour);

        secretKeys = api.modify(secretKeys, twoHoursLater)
                .revokeUserId("A", protector) // hard revoke A
                .done();
        info = api.inspect(secretKeys, twoHoursLater);

        assertTrue(info.isHardRevoked("A"));
        assertFalse(info.isHardRevoked("B"));
        assertIsPrimaryUserId("B", info);
        assertIsNotValid("A", info);

        // Three hours later
        Date threeHoursLater = new Date(now.getTime() + 3 * millisInHour);

        OpenPGPKey finalSecretKeys = secretKeys;
        assertThrows(IllegalArgumentException.class, () ->
                api.modify(finalSecretKeys, threeHoursLater).addUserId("A", protector));
    }

    @Test
    public void generateA_primaryExpire_isExpired() {
        PGPainless api = PGPainless.getInstance();
        Date now = DateUtil.now();
        OpenPGPKey secretKeys = api.generateKey(OpenPGPKeyVersion.v4, now)
                .modernKeyRing("A");
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        KeyRingInfo info = api.inspect(secretKeys);
        assertIsPrimaryUserId("A", info);

        Date later = new Date(now.getTime() + millisInHour);
        secretKeys = api.modify(secretKeys, new Date(now.getTime() + 1000)) // make sure sig is newer than default sig
                .setExpirationDate(later, protector) // expire the whole key
                .done();

        Date evenLater = new Date(now.getTime() + 2 * millisInHour);

        info = api.inspect(secretKeys, evenLater);
        assertFalse(info.isUserIdValid("A")); // is expired by now
    }

    @Test
    public void generateA_primaryB_primaryExpire_bIsStillPrimary() {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.generateKey()
                .modernKeyRing("A");
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        Date now = DateUtil.now();
        // Generate key with primary user-id A
        KeyRingInfo info = api.inspect(secretKeys);
        assertIsPrimaryUserId("A", info);

        // later set primary user-id to B
        Date t1 = new Date(now.getTime() + millisInHour);
        secretKeys = api.modify(secretKeys, t1)
                .addPrimaryUserId("B", protector)
                .done();
        info = api.inspect(secretKeys, t1);
        assertIsPrimaryUserId("B", info);
        assertIsNotPrimaryUserId("A", info);

        // Even later expire the whole key
        Date t2 = new Date(now.getTime() + 2 * millisInHour);
        Date expiration = new Date(now.getTime() + 10 * millisInHour);
        secretKeys = api.modify(secretKeys, t2)
                .setExpirationDate(expiration, protector) // expire the whole key in 1 hour
                .done();

        Date t3 = new Date(now.getTime() + 3 * millisInHour);

        info = api.inspect(secretKeys, t3);
        assertIsValid("A", info);
        assertIsValid("B", info);
        assertIsPrimaryUserId("B", info);
        assertIsNotPrimaryUserId("A", info);

        info = api.inspect(secretKeys, new Date(expiration.getTime() + 1000));
        assertIsPrimaryUserId("B", info);   // B is still primary, even though
        assertFalse(info.isUserIdValid("A"));      // key is expired by now
        assertFalse(info.isUserIdValid("B"));
    }

    @Test
    public void generateA_expire_certify() {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.generateKey().modernKeyRing("A");
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        Date now = DateUtil.now();
        Date t1 = new Date(now.getTime() + millisInHour);
        secretKeys = api.modify(secretKeys, now)
                .setExpirationDate(t1, protector)
                .done();

        Date t2 = new Date(now.getTime() + 2 * millisInHour);
        Date t4 = new Date(now.getTime() + 4 * millisInHour);
        secretKeys = api.modify(secretKeys, t2)
                .setExpirationDate(t4, protector)
                .done();

        KeyRingInfo info = api.inspect(secretKeys);
        assertIsValid("A", info);
        assertIsPrimaryUserId("A", info);
    }

    @Test
    public void generateA_expire_primaryB_expire_isPrimaryB()
            throws PGPException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.generateKey().modernKeyRing("A");
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        Date now = DateUtil.now();
        Date t1 = new Date(now.getTime() + millisInHour);
        secretKeys = api.modify(secretKeys, t1)
                .setExpirationDate(t1, protector)
                .done();

        Date t2 = new Date(now.getTime() + 2 * millisInHour);
        KeyRingInfo info = api.inspect(secretKeys, t2);

        assertIsPrimaryUserId("A", info);
        assertIsNotValid("A", info); // A is expired

        secretKeys = api.modify(secretKeys, t2)
                .addPrimaryUserId("B", protector)
                .done();

        Date t3 = new Date(now.getTime() + 3 * millisInHour);
        info = api.inspect(secretKeys, t3);

        assertIsPrimaryUserId("B", info);
        assertIsNotValid("B", info); // A and B are still expired
        assertIsNotValid("A", info);

        Date t4 = new Date(now.getTime() + 4 * millisInHour);
        Date t5 = new Date(now.getTime() + 5 * millisInHour);
        secretKeys = api.modify(secretKeys, t3)
                .setExpirationDate(t5, protector)
                .done();

        info = api.inspect(secretKeys, t4);
        assertIsValid("B", info);
        assertIsValid("A", info); // A got re-validated when changing exp date
        assertIsPrimaryUserId("B", info);

        secretKeys = api.modify(secretKeys, t4)
                .addUserId("A", protector) // re-certify A as non-primary user-id
                .done();
        info = api.inspect(secretKeys, t4);

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
