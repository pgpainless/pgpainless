package de.vanitasvitae.crypto.pgpainless.key.selection.key.impl;

import de.vanitasvitae.crypto.pgpainless.key.selection.key.PublicKeySelectionStrategy;
import org.bouncycastle.openpgp.PGPPublicKey;

/**
 * Key Selection Strategy that only accepts {@link PGPPublicKey}s which are capable of encryption.
 *
 * @param <O> Type that describes the owner of the key (not used for decision).
 */
public class EncryptionKeySelectionStrategy<O> extends PublicKeySelectionStrategy<O> {

    @Override
    public boolean accept(O identifier, PGPPublicKey key) {
        return key.isEncryptionKey();
    }
}
