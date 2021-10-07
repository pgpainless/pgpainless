// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util.selection.keyring.impl;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

public final class XMPP {

    private XMPP() {

    }

    public static class PubRingSelectionStrategy extends ExactUserId.PubRingSelectionStrategy {

        @Override
        public boolean accept(String jid, PGPPublicKeyRing keyRing) {
            if (!jid.matches("^xmpp:.+$")) {
                jid = "xmpp:" + jid;
            }
            return super.accept(jid, keyRing);
        }
    }

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
