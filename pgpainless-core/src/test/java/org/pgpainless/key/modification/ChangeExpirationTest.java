// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.JUtils;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.util.DateUtil;
import org.pgpainless.util.TestAllImplementations;

public class ChangeExpirationTest {

    private final OpenPgpV4Fingerprint subKeyFingerprint = new OpenPgpV4Fingerprint("F73FDE6439ABE210B1AF4EDD273EF7A0C749807B");

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void setExpirationDateAndThenUnsetIt_OnPrimaryKey()
            throws PGPException, IOException {

        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        KeyRingInfo sInfo = PGPainless.inspectKeyRing(secretKeys);

        assertNull(sInfo.getPrimaryKeyExpirationDate());
        assertNull(sInfo.getSubkeyExpirationDate(subKeyFingerprint));

        Date now = new Date();
        Date date = DateUtil.parseUTCDate("2020-11-27 16:10:32 UTC");
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(date, new UnprotectedKeysProtector()).done();
        sInfo = PGPainless.inspectKeyRing(secretKeys);
        assertNotNull(sInfo.getPrimaryKeyExpirationDate());
        assertEquals(date.getTime(), sInfo.getPrimaryKeyExpirationDate().getTime());
        // subkey unchanged
        assertNull(sInfo.getSubkeyExpirationDate(subKeyFingerprint));

        Date t1 = new Date(now.getTime() + 1000 * 60 * 60);
        secretKeys = PGPainless.modifyKeyRing(secretKeys, t1)
                .setExpirationDate(null, new UnprotectedKeysProtector()).done();

        sInfo = PGPainless.inspectKeyRing(secretKeys, t1);
        assertNull(sInfo.getPrimaryKeyExpirationDate());
        assertNull(sInfo.getSubkeyExpirationDate(subKeyFingerprint));
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void setExpirationDateAndThenUnsetIt_OnSubkey()
            throws PGPException, IOException {

        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        KeyRingInfo sInfo = PGPainless.inspectKeyRing(secretKeys);

        assertNull(sInfo.getPrimaryKeyExpirationDate());

        Date now = new Date();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(now);
        calendar.add(Calendar.DATE, 5);
        Date expiration = calendar.getTime(); // in 5 days

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(expiration, new UnprotectedKeysProtector()).done();
        sInfo = PGPainless.inspectKeyRing(secretKeys);
        assertNotNull(sInfo.getPrimaryKeyExpirationDate());
        JUtils.assertDateEquals(expiration, sInfo.getPrimaryKeyExpirationDate());

        Date t1 = new Date(now.getTime() + 1000 * 60 * 60);
        secretKeys = PGPainless.modifyKeyRing(secretKeys, t1)
                .setExpirationDate(null, new UnprotectedKeysProtector()).done();

        sInfo = PGPainless.inspectKeyRing(secretKeys, t1);
        assertNull(sInfo.getPrimaryKeyExpirationDate());
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testExtremeExpirationDates() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        // seconds from 2021 to 2199 will overflow 32bit integers
        Date farAwayExpiration = DateUtil.parseUTCDate("2199-01-01 00:00:00 UTC");

        final PGPSecretKeyRing finalKeys = secretKeys;
        assertThrows(IllegalArgumentException.class, () ->
                PGPainless.modifyKeyRing(finalKeys)
                        .setExpirationDate(farAwayExpiration, protector)
                        .done());

        Date notSoFarAwayExpiration = DateUtil.parseUTCDate("2100-01-01 00:00:00 UTC");

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(notSoFarAwayExpiration, protector)
                .done();

        Date actualExpiration = PGPainless.inspectKeyRing(secretKeys)
                .getPrimaryKeyExpirationDate();
        JUtils.assertDateEquals(notSoFarAwayExpiration, actualExpiration);
    }
}
