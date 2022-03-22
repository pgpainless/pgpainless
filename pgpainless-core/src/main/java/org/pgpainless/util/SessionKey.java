// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPSessionKey;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;

/**
 * A {@link SessionKey} is the symmetric key that is used to encrypt/decrypt an OpenPGP message.
 * The OpenPGP message header contains a copy of the session key, encrypted for the public key of each recipient.
 */
public class SessionKey {

    private final SymmetricKeyAlgorithm algorithm;
    private final byte[] key;

    /**
     * Constructor to create a session key from a BC {@link PGPSessionKey} object.
     *
     * @param sessionKey BC session key
     */
    public SessionKey(@Nonnull PGPSessionKey sessionKey) {
        this(SymmetricKeyAlgorithm.requireFromId(sessionKey.getAlgorithm()), sessionKey.getKey());
    }

    /**
     * Create a session key object from an algorithm and a key.
     *
     * @param algorithm algorithm
     * @param key key
     */
    public SessionKey(@Nonnull SymmetricKeyAlgorithm algorithm, @Nonnull byte[] key) {
        this.algorithm = algorithm;
        this.key = key;
    }

    /**
     * Return the symmetric key algorithm.
     *
     * @return algorithm
     */
    public SymmetricKeyAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * Return the bytes of the key.
     *
     * @return key
     */
    public byte[] getKey() {
        byte[] copy = new byte[key.length];
        System.arraycopy(key, 0, copy, 0, copy.length);
        return copy;
    }
}
