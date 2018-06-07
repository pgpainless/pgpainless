package de.vanitasvitae.crypto.pgpainless.key.selection.key.impl;

import de.vanitasvitae.crypto.pgpainless.key.selection.key.PublicKeySelectionStrategy;
import de.vanitasvitae.crypto.pgpainless.key.selection.key.SecretKeySelectionStrategy;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

/**
 * Key Selection Strategies that do accept only keys, which have no revocation.
 */
public class NoRevocation {

    /**
     * Key Selection Strategy which only accepts {@link PGPPublicKey}s which have no revocation.
     *
     * @param <O> Type that describes the owner of this key (not used for this decision).
     */
    public static class PubKeySelectionStrategy<O> extends PublicKeySelectionStrategy<O> {

        @Override
        public boolean accept(O identifier, PGPPublicKey key) {
            return !key.hasRevocation();
        }
    }

    /**
     * Key Selection Strategy which only accepts {@link PGPSecretKey}s which have no revocation.
     *
     * @param <O> Type that describes the owner of this key (not used for this decision).
     */
    public static class SecKeySelectionStrategy<O> extends SecretKeySelectionStrategy<O> {

        @Override
        public boolean accept(O identifier, PGPSecretKey key) {
            return !key.getPublicKey().hasRevocation();
        }
    }
}
