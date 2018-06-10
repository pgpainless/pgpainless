package de.vanitasvitae.crypto.pgpainless.key.selection.keyring.impl;

import de.vanitasvitae.crypto.pgpainless.key.selection.keyring.PublicKeyRingSelectionStrategy;
import de.vanitasvitae.crypto.pgpainless.key.selection.keyring.SecretKeyRingSelectionStrategy;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

public class Wildcard {

    public class PubRingSelectionStrategy<O> extends PublicKeyRingSelectionStrategy<O> {

        @Override
        public boolean accept(O identifier, PGPPublicKeyRing keyRing) {
            return true;
        }
    }

    public class SecRingSelectionStrategy<O> extends SecretKeyRingSelectionStrategy<O> {

        @Override
        public boolean accept(O identifier, PGPSecretKeyRing keyRing) {
            return true;
        }
    }
}
