/*
 * Copyright 2021 Paul Schaub.
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
package org.pgpainless.key.protection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.passphrase_provider.MapBasedPassphraseProvider;
import org.pgpainless.util.Passphrase;

public class MapBasedPassphraseProviderTest {

    @Test
    public void testMapBasedProvider() throws IOException, PGPException {
        Map<Long, Passphrase> passphraseMap = new ConcurrentHashMap<>();
        passphraseMap.put(1L, Passphrase.fromPassword("tiger"));
        passphraseMap.put(123123123L, Passphrase.fromPassword("snake"));
        passphraseMap.put(69696969L, Passphrase.emptyPassphrase());
        MapBasedPassphraseProvider provider = new MapBasedPassphraseProvider(passphraseMap);

        assertEquals(Passphrase.fromPassword("tiger"), provider.getPassphraseFor(1L));
        assertEquals(Passphrase.fromPassword("snake"), provider.getPassphraseFor(123123123L));
        assertEquals(Passphrase.emptyPassphrase(), provider.getPassphraseFor(69696969L));
        assertNull(provider.getPassphraseFor(555L));

        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();
        passphraseMap = new ConcurrentHashMap<>();
        passphraseMap.put(secretKeys.getSecretKey().getKeyID(), TestKeys.CRYPTIE_PASSPHRASE);
        provider = new MapBasedPassphraseProvider(passphraseMap);

        assertEquals(TestKeys.CRYPTIE_PASSPHRASE, provider.getPassphraseFor(secretKeys.getSecretKey()));
        assertNull(provider.getPassphraseFor(TestKeys.getEmilSecretKeyRing().getSecretKey()));
    }
}
