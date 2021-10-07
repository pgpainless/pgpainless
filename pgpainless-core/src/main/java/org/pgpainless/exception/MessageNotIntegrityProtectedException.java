// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.exception;

import org.bouncycastle.openpgp.PGPException;

public class MessageNotIntegrityProtectedException extends PGPException {

    public MessageNotIntegrityProtectedException() {
        super("Message is encrypted using a 'Symmetrically Encrypted Data' (SED) packet, which enables certain types of attacks. " +
                "A 'Symmetrically Encrypted Integrity Protected' (SEIP) packet should be used instead.");
    }
}
