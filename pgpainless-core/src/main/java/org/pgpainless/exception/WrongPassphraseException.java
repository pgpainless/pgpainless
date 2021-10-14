// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.exception;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.bouncycastle.openpgp.PGPException;

public class WrongPassphraseException extends PGPException {
    private Map<Long, Exception> keyIds = Collections.emptyMap();

    public WrongPassphraseException(String message) {
        super(message);
    }

    public WrongPassphraseException(long keyId, PGPException cause) {
        this("Wrong passphrase provided for key " + Long.toHexString(keyId), cause);
        this.keyIds = new HashMap<>();
        this.keyIds.put(keyId, cause);
    }

    public WrongPassphraseException(Map<Long, Exception> keyIds) {
        this("Wrong passphrase provided for keys: " +
                keyIds.keySet().stream().map(Long::toHexString).collect(Collectors.joining(", ")));
        this.keyIds = keyIds;
    }

    public WrongPassphraseException(String message, PGPException cause) {
        super(message, cause);
    }

    public Map<Long, Exception> getKeyIds() {
        return keyIds;
    }
}
