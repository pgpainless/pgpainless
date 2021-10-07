// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.util.DateUtil;

public class ChangeExpirationTest {

    private final OpenPgpV4Fingerprint subKeyFingerprint = new OpenPgpV4Fingerprint("F73FDE6439ABE210B1AF4EDD273EF7A0C749807B");

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void setExpirationDateAndThenUnsetIt_OnPrimaryKey(ImplementationFactory implementationFactory) throws PGPException, IOException, InterruptedException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

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

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void setExpirationDateAndThenUnsetIt_OnSubkey(ImplementationFactory implementationFactory) throws PGPException, IOException, InterruptedException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        KeyRingInfo sInfo = PGPainless.inspectKeyRing(secretKeys);

        assertNull(sInfo.getSubkeyExpirationDate(subKeyFingerprint));
        assertNull(sInfo.getPrimaryKeyExpirationDate());

        Date date = DateUtil.parseUTCDate("2020-11-27 16:10:32 UTC");
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(subKeyFingerprint, date, new UnprotectedKeysProtector()).done();
        sInfo = PGPainless.inspectKeyRing(secretKeys);
        assertNotNull(sInfo.getSubkeyExpirationDate(subKeyFingerprint));
        assertEquals(date.getTime(), sInfo.getSubkeyExpirationDate(subKeyFingerprint).getTime());
        assertNull(sInfo.getPrimaryKeyExpirationDate());

        // We need to wait for one second as OpenPGP signatures have coarse-grained (up to a second)
        // accuracy. Creating two signatures within a short amount of time will make the second one
        // "invisible"
        Thread.sleep(1100);

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(subKeyFingerprint, null, new UnprotectedKeysProtector()).done();

        sInfo = PGPainless.inspectKeyRing(secretKeys);
        assertNull(sInfo.getSubkeyExpirationDate(subKeyFingerprint));
        assertNull(sInfo.getPrimaryKeyExpirationDate());
    }
}
