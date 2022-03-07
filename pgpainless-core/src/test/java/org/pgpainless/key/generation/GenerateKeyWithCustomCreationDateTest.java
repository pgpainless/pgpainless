// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.JUtils;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.xdh.XDHSpec;
import org.pgpainless.util.DateUtil;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Iterator;

public class GenerateKeyWithCustomCreationDateTest {

    @Test
    public void generateKeyWithCustomCreationDateTest()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        Date creationDate = DateUtil.parseUTCDate("2018-06-11 14:12:09 UTC");
        PGPSecretKeyRing secretKeys = PGPainless.buildKeyRing()
                .addSubkey(KeySpec.getBuilder(KeyType.XDH(XDHSpec._X25519), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE))
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                        .setKeyCreationDate(creationDate)) // primary key with custom creation time
                .addUserId("Alice")
                .build();

        Iterator<PGPSecretKey> iterator = secretKeys.iterator();
        PGPPublicKey primaryKey = iterator.next().getPublicKey();
        PGPPublicKey subkey = iterator.next().getPublicKey();

        JUtils.assertDateEquals(creationDate, primaryKey.getCreationTime());
        // subkey has no creation date override, so it was generated "just now"
        JUtils.assertDateNotEquals(creationDate, subkey.getCreationTime());
    }
}
