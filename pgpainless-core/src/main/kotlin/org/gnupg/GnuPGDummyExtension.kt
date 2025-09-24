// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.gnupg

import org.bouncycastle.bcpg.S2K

enum class GnuPGDummyExtension(val id: Int) {

    /** Do not store the secret part at all. */
    NO_PRIVATE_KEY(S2K.GNU_PROTECTION_MODE_NO_PRIVATE_KEY),

    /** A stub to access smartcards. */
    DIVERT_TO_CARD(S2K.GNU_PROTECTION_MODE_DIVERT_TO_CARD)
}
