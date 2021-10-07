// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

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
