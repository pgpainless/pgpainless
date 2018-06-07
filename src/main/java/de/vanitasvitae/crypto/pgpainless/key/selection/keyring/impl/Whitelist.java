package de.vanitasvitae.crypto.pgpainless.key.selection.keyring.impl;

import java.util.Map;
import java.util.Set;

import de.vanitasvitae.crypto.pgpainless.key.selection.keyring.PublicKeyRingSelectionStrategy;
import de.vanitasvitae.crypto.pgpainless.key.selection.keyring.SecretKeyRingSelectionStrategy;
import de.vanitasvitae.crypto.pgpainless.util.MultiMap;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

public class Whitelist {

    public static class PubRingSelectionStrategy<O> extends PublicKeyRingSelectionStrategy<O> {

        private final MultiMap<O, Long> whitelist;

        public PubRingSelectionStrategy(MultiMap<O, Long> whitelist) {
            this.whitelist = whitelist;
        }

        public PubRingSelectionStrategy(Map<O, Set<Long>> whitelist) {
            this.whitelist = new MultiMap<>(whitelist);
        }

        @Override
        public boolean accept(O identifier, PGPPublicKeyRing keyRing) {
            Set<Long> whitelistedKeyIds = whitelist.get(identifier);

            if (whitelistedKeyIds == null) {
                return false;
            }

            return whitelistedKeyIds.contains(keyRing.getPublicKey().getKeyID());
        }
    }

    public static class SecRingSelectionStrategy<O> extends SecretKeyRingSelectionStrategy<O> {

        private final MultiMap<O, Long> whitelist;

        public SecRingSelectionStrategy(MultiMap<O, Long> whitelist) {
            this.whitelist = whitelist;
        }

        public SecRingSelectionStrategy(Map<O, Set<Long>> whitelist) {
            this.whitelist = new MultiMap<>(whitelist);
        }

        @Override
        public boolean accept(O identifier, PGPSecretKeyRing keyRing) {
            Set<Long> whitelistedKeyIds = whitelist.get(identifier);

            if (whitelistedKeyIds == null) {
                return false;
            }

            return whitelistedKeyIds.contains(keyRing.getPublicKey().getKeyID());
        }

    }
}