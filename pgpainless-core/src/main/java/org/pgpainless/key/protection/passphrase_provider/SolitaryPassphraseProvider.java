package org.pgpainless.key.protection.passphrase_provider;

import javax.annotation.Nullable;

import org.pgpainless.util.Passphrase;

public class SolitaryPassphraseProvider implements SecretKeyPassphraseProvider {

    private final Passphrase passphrase;

    public SolitaryPassphraseProvider(Passphrase passphrase) {
        this.passphrase = passphrase;
    }

    @Nullable
    @Override
    public Passphrase getPassphraseFor(Long keyId) {
        return passphrase;
    }
}
