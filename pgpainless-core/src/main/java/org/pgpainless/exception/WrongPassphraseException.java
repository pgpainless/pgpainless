// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.exception;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;

public class WrongPassphraseException extends PGPException {

    public WrongPassphraseException(String message) {
        super(message);
    }

    public WrongPassphraseException(long keyId, PGPException cause) {
        this(new KeyIdentifier(keyId), cause);
    }

    public WrongPassphraseException(KeyIdentifier keyIdentifier, PGPException cause) {
        this("Wrong passphrase provided for key " + keyIdentifier, cause);
    }

    public WrongPassphraseException(String message, PGPException cause) {
        super(message, cause);
    }
}
