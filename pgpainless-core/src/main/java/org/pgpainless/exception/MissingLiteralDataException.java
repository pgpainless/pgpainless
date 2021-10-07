// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.exception;

import org.bouncycastle.openpgp.PGPException;

/**
 * Exception that gets thrown if a {@link org.bouncycastle.bcpg.LiteralDataPacket} is expected, but not found.
 */
public class MissingLiteralDataException extends PGPException {

    public MissingLiteralDataException(String message) {
        super(message);
    }
}
