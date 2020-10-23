package org.pgpainless.key.protection.passphrase_provider;

import java.util.Map;
import javax.annotation.Nullable;

import org.pgpainless.util.Passphrase;

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
}
