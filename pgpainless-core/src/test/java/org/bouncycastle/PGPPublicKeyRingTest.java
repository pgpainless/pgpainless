// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.util.CollectionUtils;

public class PGPPublicKeyRingTest {

    /**
     * Learning test to see if BC also makes userids available on subkeys.
     * It does not.
     *
     * see also https://security.stackexchange.com/questions/92635/is-it-possible-to-assign-different-uids-to-subkeys-for-the-purpose-of-having-mul
     */
    @Test
    public void subkeysDoNotHaveUserIDsTest() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleEcKeyRing("primary@user.id");
        PGPPublicKeyRing publicKeys = KeyRingUtils.publicKeyRingFrom(secretKeys);
        PGPPublicKey primaryKey = publicKeys.getPublicKey();
        for (PGPPublicKey subkey : publicKeys) {
            Iterator<String> userIds = subkey.getUserIDs();
            if (primaryKey == subkey) {
                assertEquals("primary@user.id", userIds.next());
            }
            assertFalse(userIds.hasNext());
        }
    }

    @Test
    public void removeUserIdTest() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        String userId = "alice@wonderland.lit";
        PGPSecretKeyRing secretKeyRing = PGPainless.generateKeyRing().simpleEcKeyRing(userId);
        PGPPublicKeyRing publicKeys = KeyRingUtils.publicKeyRingFrom(secretKeyRing);

        List<String> userIds = CollectionUtils.iteratorToList(publicKeys.getPublicKey().getUserIDs());
        assertTrue(userIds.contains(userId));

        PGPPublicKey publicKey = publicKeys.getPublicKey();
        publicKey = PGPPublicKey.removeCertification(publicKey, userId);

        userIds = CollectionUtils.iteratorToList(publicKey.getUserIDs());
        assertFalse(userIds.contains(userId));
    }
}
