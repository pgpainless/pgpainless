// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.exception;

import org.bouncycastle.openpgp.PGPException;

/**
 * Exception that gets thrown if unacceptable algorithms are encountered.
 */
public class UnacceptableAlgorithmException extends PGPException {

    public UnacceptableAlgorithmException(String message) {
        super(message);
    }
}
