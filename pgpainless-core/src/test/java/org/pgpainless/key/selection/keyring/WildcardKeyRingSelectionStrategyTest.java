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

import static junit.framework.TestCase.assertTrue;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.Test;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.selection.keyring.impl.Wildcard;

public class WildcardKeyRingSelectionStrategyTest {


    Wildcard.PubRingSelectionStrategy<String> pubKeySelectionStrategy = new Wildcard.PubRingSelectionStrategy<>();
    Wildcard.SecRingSelectionStrategy<String> secKeySelectionStrategy = new Wildcard.SecRingSelectionStrategy<>();

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
