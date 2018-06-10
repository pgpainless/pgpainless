package de.vanitasvitae.crypto.pgpainless.key.selection.key.impl;

import de.vanitasvitae.crypto.pgpainless.key.selection.key.PublicKeySelectionStrategy;
import de.vanitasvitae.crypto.pgpainless.key.selection.key.SecretKeySelectionStrategy;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

public class And {

    public static class PubKeySelectionStrategy<O> extends PublicKeySelectionStrategy<O> {

        private final PublicKeySelectionStrategy<O> left;
        private final PublicKeySelectionStrategy<O> right;

        public PubKeySelectionStrategy(PublicKeySelectionStrategy<O> left,
                                       PublicKeySelectionStrategy<O> right) {
            this.left = left;
            this.right = right;
        }

        @Override
        public boolean accept(O identifier, PGPPublicKey key) {
            return left.accept(identifier, key) && right.accept(identifier, key);
        }
    }

    public static class SecKeySelectionStrategy<O> extends SecretKeySelectionStrategy<O> {

        private final SecretKeySelectionStrategy<O> left;
        private final SecretKeySelectionStrategy<O> right;

        public SecKeySelectionStrategy(SecretKeySelectionStrategy<O> left,
                                       SecretKeySelectionStrategy<O> right) {
            this.left = left;
            this.right = right;
        }

        @Override
        public boolean accept(O identifier, PGPSecretKey key) {
            return left.accept(identifier, key) && right.accept(identifier, key);
        }
    }

}
