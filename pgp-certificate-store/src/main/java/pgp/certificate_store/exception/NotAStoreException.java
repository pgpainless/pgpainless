// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store.exception;

/**
 * The base dir cannot possibly contain a store.
 */
public class NotAStoreException extends Exception {

    public NotAStoreException() {
        super();
    }

    public NotAStoreException(String message) {
        super(message);
    }
}
