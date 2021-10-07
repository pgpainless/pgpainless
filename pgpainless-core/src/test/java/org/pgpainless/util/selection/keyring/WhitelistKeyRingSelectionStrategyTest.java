// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util.selection.keyring;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.key.TestKeys;
import org.pgpainless.util.selection.keyring.impl.Whitelist;

public class WhitelistKeyRingSelectionStrategyTest {

    @Test
    public void testWithPublicKeys() throws IOException {
        Map<String, Set<Long>> ids = new ConcurrentHashMap<>();
        ids.put(TestKeys.JULIET_UID, Collections.singleton(TestKeys.JULIET_KEY_ID));
        Whitelist.PubRingSelectionStrategy<String> selectionStrategy = new Whitelist.PubRingSelectionStrategy<>(ids);

        PGPPublicKeyRing julietsKeys = TestKeys.getJulietPublicKeyRing();
        PGPPublicKeyRing romeosKeys = TestKeys.getRomeoPublicKeyRing();

        assertTrue(selectionStrategy.accept(TestKeys.JULIET_UID, julietsKeys));
        assertFalse(selectionStrategy.accept(TestKeys.JULIET_UID, romeosKeys));
        assertFalse(selectionStrategy.accept(TestKeys.ROMEO_UID, julietsKeys));
    }

    @Test
    public void testWithSecretKeys() throws IOException, PGPException {
        Map<String, Set<Long>> ids = new ConcurrentHashMap<>();
        ids.put(TestKeys.JULIET_UID, Collections.singleton(TestKeys.JULIET_KEY_ID));
        Whitelist.SecRingSelectionStrategy<String> selectionStrategy = new Whitelist.SecRingSelectionStrategy<>(ids);

        PGPSecretKeyRing julietsKeys = TestKeys.getJulietSecretKeyRing();
        PGPSecretKeyRing romeosKeys = TestKeys.getRomeoSecretKeyRing();

        assertTrue(selectionStrategy.accept(TestKeys.JULIET_UID, julietsKeys));
        assertFalse(selectionStrategy.accept(TestKeys.JULIET_UID, romeosKeys));
        assertFalse(selectionStrategy.accept(TestKeys.ROMEO_UID, julietsKeys));
    }
}
