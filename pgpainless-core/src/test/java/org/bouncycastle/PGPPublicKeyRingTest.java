// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Iterator;
import java.util.List;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.util.CollectionUtils;

public class PGPPublicKeyRingTest {

    private final PGPainless api = PGPainless.getInstance();

    /**
     * Learning test to see if BC also makes userids available on subkeys.
     * It does not.
     *
     * @see <a href="https://security.stackexchange.com/questions/92635/is-it-possible-to-assign-different-uids-to-subkeys-for-the-purpose-of-having-mul>Stackexchange link</a>
     */
    @Test
    public void subkeysDoNotHaveUserIDsTest() {
        OpenPGPKey key = api.generateKey().simpleEcKeyRing("primary@user.id");
        OpenPGPCertificate certificate = key.toCertificate();
        for (OpenPGPCertificate.OpenPGPComponentKey subkey : certificate.getSubkeys().values()) {
            Iterator<String> userIds = subkey.getPGPPublicKey().getUserIDs();
            assertFalse(userIds.hasNext());
        }
    }

    @Test
    public void removeUserIdTest() {
        String userId = "alice@wonderland.lit";
        OpenPGPKey key = api.generateKey().simpleEcKeyRing(userId);
        OpenPGPCertificate certificate = key.toCertificate();
        PGPPublicKey publicKey = certificate.getPrimaryKey().getPGPPublicKey();

        List<String> userIds = CollectionUtils.iteratorToList(publicKey.getUserIDs());
        assertTrue(userIds.contains(userId));

        publicKey = PGPPublicKey.removeCertification(publicKey, userId);

        userIds = CollectionUtils.iteratorToList(publicKey.getUserIDs());
        assertFalse(userIds.contains(userId));
    }
}
