package de.vanitasvitae.crypto.pgpainless.key.selection.key.impl;

import de.vanitasvitae.crypto.pgpainless.key.selection.key.SecretKeySelectionStrategy;
import org.bouncycastle.openpgp.PGPSecretKey;

/**
 * Key Selection Strategy that only accepts {@link PGPSecretKey}s which are capable of signing.
 *
 * @param <O> Type that describes the owner of the key (not used for this decision).
 */
public class SignatureKeySelectionStrategy<O> extends SecretKeySelectionStrategy<O> {

    @Override
    public boolean accept(O identifier, PGPSecretKey key) {
        return key.isSigningKey();
    }

}
