// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.exception;

import org.bouncycastle.openpgp.PGPException;

/**
 * Exception that is thrown when decryption fails due to a missing decryption key or decryption passphrase.
 * This can happen when the user does not provide the right set of keys / the right password when decrypting
 * a message.
 */
public class MissingDecryptionMethodException extends PGPException {

    public MissingDecryptionMethodException(String message) {
        super(message);
    }
}
