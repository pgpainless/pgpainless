/*
 * Copyright 2020 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.key.selection.keyring;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.selection.keyring.impl.XMPP;

public class XmppKeyRingSelectionStrategyTest {

    XMPP.PubRingSelectionStrategy pubKeySelectionStrategy = new XMPP.PubRingSelectionStrategy();
    XMPP.SecRingSelectionStrategy secKeySelectionStrategy = new XMPP.SecRingSelectionStrategy();

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
