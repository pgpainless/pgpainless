// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.passphrase_provider.MapBasedPassphraseProvider;
import org.pgpainless.util.Passphrase;

public class MapBasedPassphraseProviderTest {

    @Test
    public void testMapBasedProvider() throws IOException, PGPException {
        Map<KeyIdentifier, Passphrase> passphraseMap = new ConcurrentHashMap<>();
        passphraseMap.put(new KeyIdentifier(1L), Passphrase.fromPassword("tiger"));
        passphraseMap.put(new KeyIdentifier(123123123L), Passphrase.fromPassword("snake"));
        passphraseMap.put(new KeyIdentifier(69696969L), Passphrase.emptyPassphrase());
        MapBasedPassphraseProvider provider = new MapBasedPassphraseProvider(passphraseMap);

        assertEquals(Passphrase.fromPassword("tiger"), provider.getPassphraseFor(new KeyIdentifier(1L)));
        assertEquals(Passphrase.fromPassword("snake"), provider.getPassphraseFor(new KeyIdentifier((123123123L))));
        assertEquals(Passphrase.emptyPassphrase(), provider.getPassphraseFor(new KeyIdentifier(69696969L)));
        assertNull(provider.getPassphraseFor(new KeyIdentifier(555L)));

        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();
        passphraseMap = new ConcurrentHashMap<>();
        passphraseMap.put(secretKeys.getSecretKey().getKeyIdentifier(), TestKeys.CRYPTIE_PASSPHRASE);
        provider = new MapBasedPassphraseProvider(passphraseMap);

        assertEquals(TestKeys.CRYPTIE_PASSPHRASE, provider.getPassphraseFor(secretKeys.getSecretKey()));
        assertNull(provider.getPassphraseFor(TestKeys.getEmilSecretKeyRing().getSecretKey()));
    }
}
