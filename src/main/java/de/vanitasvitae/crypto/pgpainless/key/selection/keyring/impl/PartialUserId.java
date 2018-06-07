package de.vanitasvitae.crypto.pgpainless.key.selection.keyring.impl;

import java.util.Iterator;

import de.vanitasvitae.crypto.pgpainless.key.selection.key.PublicKeySelectionStrategy;
import de.vanitasvitae.crypto.pgpainless.key.selection.key.SecretKeySelectionStrategy;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

public class PartialUserId {

    public static class PubRingSelectionStrategy extends PublicKeySelectionStrategy<String> {

        @Override
        public boolean accept(String identifier, PGPPublicKey key) {
            for (Iterator<String> userIds = key.getUserIDs(); userIds.hasNext(); ) {
                String userId = userIds.next();
                if (userId.contains(identifier)) {
                    return true;
                }
            }
            return false;
        }
    }

    public static class SecRingSelectionStrategy extends SecretKeySelectionStrategy<String> {

        @Override
        public boolean accept(String identifier, PGPSecretKey key) {
            for (Iterator userIds = key.getUserIDs(); userIds.hasNext(); ) {
                String userId = (String) userIds.next();
                if (userId.contains(identifier)) {
                    return true;
                }
            }
            return false;
        }
    }
}
