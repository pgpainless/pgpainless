// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection.passphrase_provider;

import javax.annotation.Nullable;

import org.pgpainless.util.Passphrase;

/**
 * Implementation of the {@link SecretKeyPassphraseProvider} that holds a single {@link Passphrase}.
 */
public class SolitaryPassphraseProvider implements SecretKeyPassphraseProvider {

    private final Passphrase passphrase;

    public SolitaryPassphraseProvider(Passphrase passphrase) {
        this.passphrase = passphrase;
    }

    @Nullable
    @Override
    public Passphrase getPassphraseFor(Long keyId) {
        // always return the same passphrase.
        return passphrase;
    }

    @Override
    public boolean hasPassphrase(Long keyId) {
        return true;
    }
}
