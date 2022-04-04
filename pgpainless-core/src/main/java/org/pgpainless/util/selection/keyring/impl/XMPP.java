// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util.selection.keyring.impl;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

/**
 * Implementations of {@link org.pgpainless.util.selection.keyring.KeyRingSelectionStrategy} which accept KeyRings
 * containing a given XMPP address of the format "xmpp:alice@pgpainless.org".
 */
public final class XMPP {

    private XMPP() {

    }

    /**
     * {@link org.pgpainless.util.selection.keyring.PublicKeyRingSelectionStrategy} which accepts a given
     * {@link PGPPublicKeyRing} if its primary key has a user-id that matches the given <pre>jid</pre>.
     *
     * The argument <pre>jid</pre> can either contain the prefix "xmpp:", or not, the result will be the same.
     */
    public static class PubRingSelectionStrategy extends ExactUserId.PubRingSelectionStrategy {

        @Override
        public boolean accept(String jid, PGPPublicKeyRing keyRing) {
            if (!jid.matches("^xmpp:.+$")) {
                jid = "xmpp:" + jid;
            }
            return super.accept(jid, keyRing);
        }
    }

    /**
     * {@link org.pgpainless.util.selection.keyring.SecretKeyRingSelectionStrategy} which accepts a given
     * {@link PGPSecretKeyRing} if its primary key has a user-id that matches the given <pre>jid</pre>.
     *
     * The argument <pre>jid</pre> can either contain the prefix "xmpp:", or not, the result will be the same.
     */
    public static class SecRingSelectionStrategy extends ExactUserId.SecRingSelectionStrategy {

        @Override
        public boolean accept(String jid, PGPSecretKeyRing keyRing) {
            if (!jid.matches("^xmpp:.+$")) {
                jid = "xmpp:" + jid;
            }
            return super.accept(jid, keyRing);
        }
    }
}
