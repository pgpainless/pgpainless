// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.JUtils;
import org.pgpainless.PGPainless;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.util.DateUtil;
import org.pgpainless.util.TestAllImplementations;

public class ChangeExpirationTest {

    private final OpenPgpV4Fingerprint subKeyFingerprint = new OpenPgpV4Fingerprint("F73FDE6439ABE210B1AF4EDD273EF7A0C749807B");

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void setExpirationDateAndThenUnsetIt_OnPrimaryKey()
            throws PGPException, IOException, InterruptedException {

        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        KeyRingInfo sInfo = PGPainless.inspectKeyRing(secretKeys);

        assertNull(sInfo.getPrimaryKeyExpirationDate());
        assertNull(sInfo.getSubkeyExpirationDate(subKeyFingerprint));

        Date date = DateUtil.parseUTCDate("2020-11-27 16:10:32 UTC");
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(date, new UnprotectedKeysProtector()).done();
        sInfo = PGPainless.inspectKeyRing(secretKeys);
        assertNotNull(sInfo.getPrimaryKeyExpirationDate());
        assertEquals(date.getTime(), sInfo.getPrimaryKeyExpirationDate().getTime());
        // subkey unchanged
        assertNull(sInfo.getSubkeyExpirationDate(subKeyFingerprint));

        // We need to wait for one second as OpenPGP signatures have coarse-grained (up to a second)
        // accuracy. Creating two signatures within a short amount of time will make the second one
        // "invisible"
        Thread.sleep(1100);

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(null, new UnprotectedKeysProtector()).done();

        sInfo = PGPainless.inspectKeyRing(secretKeys);
        assertNull(sInfo.getPrimaryKeyExpirationDate());
        assertNull(sInfo.getSubkeyExpirationDate(subKeyFingerprint));
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void setExpirationDateAndThenUnsetIt_OnSubkey()
            throws PGPException, IOException, InterruptedException {

        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        KeyRingInfo sInfo = PGPainless.inspectKeyRing(secretKeys);

        assertNull(sInfo.getPrimaryKeyExpirationDate());

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.add(Calendar.DATE, 5);
        Date expiration = calendar.getTime();
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(expiration, new UnprotectedKeysProtector()).done();
        sInfo = PGPainless.inspectKeyRing(secretKeys);
        assertNotNull(sInfo.getPrimaryKeyExpirationDate());
        JUtils.assertDateEquals(expiration, sInfo.getPrimaryKeyExpirationDate());

        // We need to wait for one second as OpenPGP signatures have coarse-grained (up to a second)
        // accuracy. Creating two signatures within a short amount of time will make the second one
        // "invisible"
        Thread.sleep(1100);

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(null, new UnprotectedKeysProtector()).done();

        sInfo = PGPainless.inspectKeyRing(secretKeys);
        assertNull(sInfo.getPrimaryKeyExpirationDate());
    }
}
