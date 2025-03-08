// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.JUtils;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve;
import org.pgpainless.key.generation.type.xdh_legacy.XDHLegacySpec;
import org.pgpainless.util.DateUtil;

public class GenerateKeyWithCustomCreationDateTest {

    @Test
    public void generateKeyWithCustomCreationDateTest() {
        Date creationDate = DateUtil.parseUTCDate("2018-06-11 14:12:09 UTC");
        PGPSecretKeyRing secretKeys = PGPainless.buildKeyRing()
                .addSubkey(KeySpec.getBuilder(KeyType.XDH_LEGACY(XDHLegacySpec._X25519), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE))
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                        .setKeyCreationDate(creationDate)) // primary key with custom creation time
                .addUserId("Alice")
                .build()
                .getPGPSecretKeyRing();

        Iterator<PGPSecretKey> iterator = secretKeys.iterator();
        PGPPublicKey primaryKey = iterator.next().getPublicKey();
        PGPPublicKey subkey = iterator.next().getPublicKey();

        JUtils.assertDateEquals(creationDate, primaryKey.getCreationTime());
        // subkey has no creation date override, so it was generated "just now"
        JUtils.assertDateNotEquals(creationDate, subkey.getCreationTime());
    }

    @Test
    public void generateSubkeyWithFutureKeyCreationDate() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.YEAR, 20);
        Date future = calendar.getTime();

        PGPSecretKeyRing secretKeys = PGPainless.buildKeyRing()
                .addSubkey(KeySpec.getBuilder(KeyType.ECDH(EllipticCurve._P384), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE).setKeyCreationDate(future))
                .setPrimaryKey(KeySpec.getBuilder(KeyType.ECDSA(EllipticCurve._P384), KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA))
                .addUserId("Captain Future <cpt@futu.re>")
                .build()
                .getPGPSecretKeyRing();

        // Subkey has future key creation date, so its binding will predate the key -> no usable encryption key left
        assertFalse(PGPainless.inspectKeyRing(secretKeys)
                .isUsableForEncryption());
    }
}
