// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>, 2021 Flowcrypt a.s.
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;

public class ChangePrimaryUserIdAndExpirationDatesTest {

    @Test
    public void generateA_primaryB_revokeA_cantSecondaryA()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InterruptedException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("A", null);
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        assertFalse(info.isHardRevoked("A"));
        assertFalse(info.isHardRevoked("B"));
        assertIsPrimaryUserId("A", info);
        assertIsNotValid("B", info);
        assertIsNotPrimaryUserId("B", info);

        Thread.sleep(1000);

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addPrimaryUserId("B", protector)
                .done();
        info = PGPainless.inspectKeyRing(secretKeys);

        assertIsPrimaryUserId("B", info);
        assertIsNotPrimaryUserId("A", info);

        Thread.sleep(1000);

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .revokeUserId("A", protector) // hard revoke A
                .done();
        info = PGPainless.inspectKeyRing(secretKeys);

        assertTrue(info.isHardRevoked("A"));
        assertFalse(info.isHardRevoked("B"));
        assertIsPrimaryUserId("B", info);
        assertIsNotValid("A", info);

        Thread.sleep(1000);

        PGPSecretKeyRing finalSecretKeys = secretKeys;
        assertThrows(IllegalArgumentException.class, () ->
                PGPainless.modifyKeyRing(finalSecretKeys).addUserId("A", protector));
    }

    @Test
    public void generateA_primaryExpire_isExpired()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InterruptedException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("A", null);
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        assertIsPrimaryUserId("A", info);

        Thread.sleep(1000);

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(new Date(), protector) // expire the whole key
                .done();

        Thread.sleep(1000);

        info = PGPainless.inspectKeyRing(secretKeys);
        assertFalse(info.isUserIdValid("A")); // is expired by now
    }

    @Test
    public void generateA_primaryB_primaryExpire_bIsStillPrimary()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InterruptedException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("A", null);
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        assertIsPrimaryUserId("A", info);

        Thread.sleep(1000);

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addPrimaryUserId("B", protector)
                .done();
        info = PGPainless.inspectKeyRing(secretKeys);

        assertIsPrimaryUserId("B", info);
        assertIsNotPrimaryUserId("A", info);

        Thread.sleep(1000);

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(new Date(new Date().getTime() + 1000), protector) // expire the whole key in 1 sec
                .done();

        info = PGPainless.inspectKeyRing(secretKeys);
        assertIsValid("A", info);
        assertIsValid("B", info);
        assertIsPrimaryUserId("B", info);
        assertIsNotPrimaryUserId("A", info);

        Thread.sleep(2000);

        info = PGPainless.inspectKeyRing(secretKeys);
        assertIsPrimaryUserId("B", info);   // B is still primary, even though
        assertFalse(info.isUserIdValid("A"));      // key is expired by now
        assertFalse(info.isUserIdValid("B"));
    }

    @Test
    public void generateA_expire_certify() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InterruptedException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing("A", null);
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(new Date(new Date().getTime() + 1000), protector)
                .done();

        Thread.sleep(2000);

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(new Date(new Date().getTime() + 2000), protector)
                .done();

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        assertIsValid("A", info);
        assertIsPrimaryUserId("A", info);
    }

    @Test
    public void generateA_expire_primaryB_expire_isPrimaryB()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InterruptedException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing("A", null);
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        Thread.sleep(1000);

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(new Date(), protector)
                .done();

        Thread.sleep(2000);
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);

        assertIsPrimaryUserId("A", info);
        assertIsNotValid("A", info); // A is expired

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addPrimaryUserId("B", protector)
                .done();

        info = PGPainless.inspectKeyRing(secretKeys);

        assertIsPrimaryUserId("B", info);
        assertIsNotValid("B", info); // A and B are still expired
        assertIsNotValid("A", info);

        Thread.sleep(1000);

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(new Date(new Date().getTime() + 10000), protector)
                .done();

        Thread.sleep(1000);
        info = PGPainless.inspectKeyRing(secretKeys);

        assertIsValid("B", info);
        assertIsValid("A", info); // A got re-validated when changing exp date
        assertIsPrimaryUserId("B", info);

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .addUserId("A", protector) // re-certify A as non-primary user-id
                .done();
        info = PGPainless.inspectKeyRing(secretKeys);

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
