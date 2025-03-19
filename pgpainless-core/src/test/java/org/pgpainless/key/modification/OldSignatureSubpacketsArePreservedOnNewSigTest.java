// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.Date;

import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.util.TestAllImplementations;

public class OldSignatureSubpacketsArePreservedOnNewSigTest {

    private static final long millisInHour = 1000 * 60 * 60;

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void verifyOldSignatureSubpacketsArePreservedOnNewExpirationDateSig() {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.generateKey()
                .simpleEcKeyRing("Alice <alice@wonderland.lit>");

        PGPSignature oldSignature = api.inspect(secretKeys).getLatestUserIdCertification("Alice <alice@wonderland.lit>");
        assertNotNull(oldSignature);
        PGPSignatureSubpacketVector oldPackets = oldSignature.getHashedSubPackets();

        long oldExpiration = oldPackets.getKeyExpirationTime();

        Date now = new Date();
        Date t1 = new Date(now.getTime() + millisInHour);
        Date expiration = new Date(now.getTime() + 5 * 24 * millisInHour); // in 5 days

        secretKeys = api.modify(secretKeys, t1)
                .setExpirationDate(expiration, new UnprotectedKeysProtector())
                .done();
        PGPSignature newSignature = api.inspect(secretKeys, t1).getLatestUserIdCertification("Alice <alice@wonderland.lit>");
        assertNotNull(newSignature);
        PGPSignatureSubpacketVector newPackets = newSignature.getHashedSubPackets();

        assertNotEquals(oldExpiration, newPackets.getKeyExpirationTime());

        assertArrayEquals(oldPackets.getPreferredHashAlgorithms(), newPackets.getPreferredHashAlgorithms());
    }
}
