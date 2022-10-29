// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.gnupg;

import org.bouncycastle.bcpg.S2K;

public enum GnuPGDummyExtension {

    /**
     * Do not store the secret part at all.
     */
    NO_PRIVATE_KEY(S2K.GNU_PROTECTION_MODE_NO_PRIVATE_KEY),

    /**
     * A stub to access smartcards.
     */
    DIVERT_TO_CARD(S2K.GNU_PROTECTION_MODE_DIVERT_TO_CARD),
    ;

    private final int id;

    GnuPGDummyExtension(int id) {
        this.id = id;
    }

    public int getId() {
        return id;
    }
}
