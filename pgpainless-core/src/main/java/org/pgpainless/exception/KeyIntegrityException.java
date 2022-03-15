// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.exception;

/**
 * This exception gets thrown, when the integrity of an OpenPGP key is broken.
 * That could happen on accident, or during an active attack, so take this exception seriously.
 */
public class KeyIntegrityException extends AssertionError {

    public KeyIntegrityException() {
        super("Key Integrity Exception");
    }
}
