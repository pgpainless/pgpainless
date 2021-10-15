// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPSessionKey;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;

public class SessionKey {

    private SymmetricKeyAlgorithm algorithm;
    private byte[] key;

    public SessionKey(@Nonnull PGPSessionKey sessionKey) {
        this(SymmetricKeyAlgorithm.fromId(sessionKey.getAlgorithm()), sessionKey.getKey());
    }

    public SessionKey(@Nonnull SymmetricKeyAlgorithm algorithm, @Nonnull byte[] key) {
        this.algorithm = algorithm;
        this.key = key;
    }

    public SymmetricKeyAlgorithm getAlgorithm() {
        return algorithm;
    }

    public byte[] getKey() {
        byte[] copy = new byte[key.length];
        System.arraycopy(key, 0, copy, 0, copy.length);
        return copy;
    }
}
