// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.util.TestAllImplementations;

public class OldSignatureSubpacketsArePreservedOnNewSig {

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void verifyOldSignatureSubpacketsArePreservedOnNewExpirationDateSig()
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, InterruptedException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .simpleEcKeyRing("Alice <alice@wonderland.lit>");

        PGPSignature oldSignature = PGPainless.inspectKeyRing(secretKeys).getLatestUserIdCertification("Alice <alice@wonderland.lit>");
        PGPSignatureSubpacketVector oldPackets = oldSignature.getHashedSubPackets();

        assertEquals(0, oldPackets.getKeyExpirationTime());

        Thread.sleep(1000);
        Date now = new Date();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(now);
        calendar.add(Calendar.DATE, 5);
        Date expiration = calendar.getTime(); // in 5 days

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(expiration, new UnprotectedKeysProtector())
                .done();
        PGPSignature newSignature = PGPainless.inspectKeyRing(secretKeys).getLatestUserIdCertification("Alice <alice@wonderland.lit>");
        PGPSignatureSubpacketVector newPackets = newSignature.getHashedSubPackets();

        assertNotEquals(0, newPackets.getKeyExpirationTime());

        assertArrayEquals(oldPackets.getPreferredHashAlgorithms(), newPackets.getPreferredHashAlgorithms());
    }
}
