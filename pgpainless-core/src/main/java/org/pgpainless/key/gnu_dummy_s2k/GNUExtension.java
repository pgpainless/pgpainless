// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.gnu_dummy_s2k;

import org.bouncycastle.bcpg.S2K;

public enum GNUExtension {

    NO_PRIVATE_KEY(S2K.GNU_PROTECTION_MODE_NO_PRIVATE_KEY),
    DIVERT_TO_CARD(S2K.GNU_PROTECTION_MODE_DIVERT_TO_CARD),
    ;

    private final int id;

    GNUExtension(int id) {
        this.id = id;
    }

    public int getId() {
        return id;
    }
}
