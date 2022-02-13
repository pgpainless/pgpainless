// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store.exception;

/**
 * Provided name was neither a valid fingerprint, nor a known special name.
 */
public class BadNameException extends Exception {

    public BadNameException() {
        super();
    }

    public BadNameException(String message) {
        super(message);
    }
}
