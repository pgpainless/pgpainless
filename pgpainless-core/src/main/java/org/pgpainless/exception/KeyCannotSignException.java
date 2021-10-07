// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.exception;

import org.bouncycastle.openpgp.PGPException;

public class KeyCannotSignException extends PGPException {
    public KeyCannotSignException(String message) {
        super(message);
    }
}
