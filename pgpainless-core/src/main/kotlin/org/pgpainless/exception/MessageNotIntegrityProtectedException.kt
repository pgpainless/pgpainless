// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.exception

import org.bouncycastle.openpgp.PGPException

class MessageNotIntegrityProtectedException :
    PGPException(
        "Message is encrypted using a 'Symmetrically Encrypted Data' (SED) packet, which enables certain types of attacks. " +
            "A 'Symmetrically Encrypted Integrity Protected' (SEIP) packet should be used instead.",
    )
