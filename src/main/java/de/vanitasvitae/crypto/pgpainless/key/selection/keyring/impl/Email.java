package de.vanitasvitae.crypto.pgpainless.key.selection.keyring.impl;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

public class Email {

    public static class PubRingSelectionStrategy extends PartialUserId.PubRingSelectionStrategy {

        @Override
        public boolean accept(String email, PGPPublicKey key) {
            // Ensure, that email address is encapsulated in "<",">"
            if (!email.matches("^<.+>$")) {
                email = "<" + email + ">";
            }
            return super.accept(email, key);
        }
    }

    public static class SecRingSelectionStrategy extends PartialUserId.SecRingSelectionStrategy {

        @Override
        public boolean accept(String email, PGPSecretKey key) {
            // Ensure, that email address is encapsulated in "<",">"
            if (!email.matches("^<.+>$")) {
                email = "<" + email + ">";
            }
            return super.accept(email, key);
        }
    }
}
