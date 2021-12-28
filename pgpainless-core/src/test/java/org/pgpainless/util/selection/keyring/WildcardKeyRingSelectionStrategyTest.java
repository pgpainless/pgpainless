// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util.selection.keyring;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.key.TestKeys;
import org.pgpainless.util.selection.keyring.impl.Wildcard;

public class WildcardKeyRingSelectionStrategyTest {


    private static final Wildcard.PubRingSelectionStrategy<String> pubKeySelectionStrategy
            = new Wildcard.PubRingSelectionStrategy<>();
    private static final Wildcard.SecRingSelectionStrategy<String> secKeySelectionStrategy
            = new Wildcard.SecRingSelectionStrategy<>();

    @Test
    public void testStratAcceptsMatchingUIDsOnPubKey() throws IOException {
        String uid = TestKeys.EMIL_UID;
        PGPPublicKeyRing key = TestKeys.getEmilPublicKeyRing();

        assertTrue(pubKeySelectionStrategy.accept(uid, key));
    }

    @Test
    public void testStratAcceptsMismatchingUIDsOnPubKey() throws IOException {
        String uid = "blabla@bla.bla";
        PGPPublicKeyRing key = TestKeys.getEmilPublicKeyRing();

        assertTrue(pubKeySelectionStrategy.accept(uid, key));
    }

    @Test
    public void testStratAcceptsMatchingUIDsOnSecKey() throws IOException, PGPException {
        String uid = TestKeys.EMIL_UID;
        PGPSecretKeyRing key = TestKeys.getEmilSecretKeyRing();

        assertTrue(secKeySelectionStrategy.accept(uid, key));
    }

    @Test
    public void testStratAcceptsMismatchingUIDsOnSecKey() throws IOException, PGPException {
        String uid = "blabla@bla.bla";
        PGPSecretKeyRing key = TestKeys.getEmilSecretKeyRing();

        assertTrue(secKeySelectionStrategy.accept(uid, key));
    }
}
