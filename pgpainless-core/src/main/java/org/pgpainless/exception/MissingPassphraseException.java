// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.exception;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;

import org.bouncycastle.openpgp.PGPException;
import org.pgpainless.key.SubkeyIdentifier;

public class MissingPassphraseException extends PGPException {

    private final Set<SubkeyIdentifier> keyIds;

    public MissingPassphraseException(Set<SubkeyIdentifier> keyIds) {
        super("Missing passphrase encountered for keys " + Arrays.toString(keyIds.toArray()));
        this.keyIds = Collections.unmodifiableSet(keyIds);
    }

    public Set<SubkeyIdentifier> getKeyIds() {
        return keyIds;
    }
}
