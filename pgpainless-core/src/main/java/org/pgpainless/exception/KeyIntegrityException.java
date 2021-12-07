// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.exception;

public class KeyIntegrityException extends AssertionError {

    public KeyIntegrityException() {
        super("Key Integrity Exception");
    }
}
