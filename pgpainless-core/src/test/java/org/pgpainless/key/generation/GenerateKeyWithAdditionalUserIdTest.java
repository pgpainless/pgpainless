// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.JUtils;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.key.util.UserId;
import org.pgpainless.util.DateUtil;
import org.pgpainless.util.ImplementationFactoryTestInvocationContextProvider;

public class GenerateKeyWithAdditionalUserIdTest {

    @TestTemplate
    @ExtendWith(ImplementationFactoryTestInvocationContextProvider.class)
    public void test() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {
        Date expiration = new Date(DateUtil.now().getTime() + 60 * 1000);
        PGPSecretKeyRing secretKeys = PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(
                        KeyType.RSA(RsaLength._3072),
                                KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA, KeyFlag.ENCRYPT_COMMS))
                .addUserId(UserId.onlyEmail("primary@user.id"))
                .addUserId(UserId.onlyEmail("additional@user.id"))
                .addUserId(UserId.onlyEmail("additional2@user.id"))
                .addUserId("\ttrimThis@user.id     ")
                .setExpirationDate(expiration)
                .build();
        PGPPublicKeyRing publicKeys = KeyRingUtils.publicKeyRingFrom(secretKeys);

        JUtils.assertEquals(expiration.getTime(), PGPainless.inspectKeyRing(publicKeys).getPrimaryKeyExpirationDate().getTime(), 2000);

        Iterator<String> userIds = publicKeys.getPublicKey().getUserIDs();
        assertEquals("primary@user.id", userIds.next());
        assertEquals("additional@user.id", userIds.next());
        assertEquals("additional2@user.id", userIds.next());
        assertEquals("trimThis@user.id", userIds.next());
        assertFalse(userIds.hasNext());
    }
}
