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
package org.pgpainless.key.protection.passphrase_provider;

import java.util.Map;
import javax.annotation.Nullable;

import org.pgpainless.util.Passphrase;

/**
 * Implementation of the {@link SecretKeyPassphraseProvider} that holds a map of different {@link Passphrase passphrases}.
 * It will return the right passphrase depending on the key-id.
 *
 * Note: This provider might return null!
 * TODO: Make this null-safe and throw an exception instead?
 */
public class MapBasedPassphraseProvider implements SecretKeyPassphraseProvider {

    private final Map<Long, Passphrase> map;

    /**
     * Create a new map based passphrase provider.
     *
     * @param passphraseMap map of key-ids and passphrases
     */
    public MapBasedPassphraseProvider(Map<Long, Passphrase> passphraseMap) {
        this.map = passphraseMap;
    }

    @Nullable
    @Override
    public Passphrase getPassphraseFor(Long keyId) {
        return map.get(keyId);
    }

    @Override
    public boolean hasPassphrase(Long keyId) {
        return map.containsKey(keyId);
    }
}
