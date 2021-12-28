// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util.selection.keyring;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.key.TestKeys;
import org.pgpainless.util.selection.keyring.impl.XMPP;

public class XmppKeyRingSelectionStrategyTest {

    private static final XMPP.PubRingSelectionStrategy pubKeySelectionStrategy =
            new XMPP.PubRingSelectionStrategy();
    private static final XMPP.SecRingSelectionStrategy secKeySelectionStrategy =
            new XMPP.SecRingSelectionStrategy();

    @Test
    public void testMatchingXmppUIDAcceptedOnPubKey() throws IOException {
        String uid = "xmpp:juliet@capulet.lit";
        PGPPublicKeyRing key = TestKeys.getJulietPublicKeyRing();

        assertTrue(pubKeySelectionStrategy.accept(uid, key));
    }

    @Test
    public void testAddressIsFormattedToMatchOnPubKey() throws IOException {
        String uid = "juliet@capulet.lit";
        PGPPublicKeyRing key = TestKeys.getJulietPublicKeyRing();

        assertTrue(pubKeySelectionStrategy.accept(uid, key));
    }

    @Test
    public void testPubKeyWithDifferentUIDIsRejected() throws IOException {
        String wrongUid = "romeo@montague.lit";
        PGPPublicKeyRing key = TestKeys.getJulietPublicKeyRing();
        assertFalse(pubKeySelectionStrategy.accept(wrongUid, key));
    }

    @Test
    public void testMatchingEmailUIDAcceptedOnSecKey() throws IOException, PGPException {
        String uid = "xmpp:juliet@capulet.lit";
        PGPSecretKeyRing key = TestKeys.getJulietSecretKeyRing();

        assertTrue(secKeySelectionStrategy.accept(uid, key));
    }

    @Test
    public void testAddressIsFormattedToMatchOnSecKey() throws IOException, PGPException {
        String uid = "juliet@capulet.lit";
        PGPSecretKeyRing key = TestKeys.getJulietSecretKeyRing();

        assertTrue(secKeySelectionStrategy.accept(uid, key));
    }

    @Test
    public void testSecKeyWithDifferentUIDIsRejected() throws IOException, PGPException {
        String wrongUid = "romeo@montague.lit";

        PGPSecretKeyRing key = TestKeys.getJulietSecretKeyRing();
        assertFalse(secKeySelectionStrategy.accept(wrongUid, key));
    }
}
