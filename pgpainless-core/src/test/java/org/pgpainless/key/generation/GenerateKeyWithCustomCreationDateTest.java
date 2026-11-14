// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
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
        PGPainless api = PGPainless.getInstance();
        Date creationDate = DateUtil.parseUTCDate("2018-06-11 14:12:09 UTC");
        OpenPGPKey secretKeys = api.buildKey()
                .addSubkey(KeySpec.getBuilder(KeyType.XDH_LEGACY(XDHLegacySpec._X25519), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE))
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                        .setKeyCreationDate(creationDate)) // primary key with custom creation time
                .addUserId("Alice")
                .build();

        OpenPGPCertificate.OpenPGPComponentKey primaryKey = secretKeys.getPrimaryKey();
        OpenPGPCertificate.OpenPGPComponentKey subkey = secretKeys.getSubkeys().values().iterator().next();

        JUtils.assertDateEquals(creationDate, primaryKey.getCreationTime());
        // subkey has no creation date override, so it was generated "just now"
        JUtils.assertDateNotEquals(creationDate, subkey.getCreationTime());
    }

    @Test
    public void generateSubkeyWithFutureKeyCreationDate() {
        PGPainless api = PGPainless.getInstance();
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.YEAR, 20);
        Date future = calendar.getTime();

        OpenPGPKey secretKeys = api.buildKey()
                .addSubkey(KeySpec.getBuilder(KeyType.ECDH(EllipticCurve._P384), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE).setKeyCreationDate(future))
                .setPrimaryKey(KeySpec.getBuilder(KeyType.ECDSA(EllipticCurve._P384), KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA))
                .addUserId("Captain Future <cpt@futu.re>")
                .build();

        // Subkey has future key creation date, so its binding will predate the key -> no usable encryption key left
        assertFalse(api.inspect(secretKeys)
                .isUsableForEncryption());
    }
}
