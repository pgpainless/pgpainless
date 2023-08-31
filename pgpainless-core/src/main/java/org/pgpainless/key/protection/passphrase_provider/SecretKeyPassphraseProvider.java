// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection.passphrase_provider;

import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPSecretKey;
import org.pgpainless.util.Passphrase;

/**
 * Interface to allow the user to provide a {@link Passphrase} for an encrypted OpenPGP secret key.
 */
public interface SecretKeyPassphraseProvider {

    /**
     * Return a passphrase for the given secret key.
     * If no record is found, return null.
     * Note: In case of an unprotected secret key, this method must may not return null, but a {@link Passphrase} with
     * a content of null.
     *
     * @param secretKey secret key
     * @return passphrase or null, if no passphrase record is found.
     */
    @Nullable default Passphrase getPassphraseFor(PGPSecretKey secretKey) {
        return getPassphraseFor(secretKey.getKeyID());
    }
    /**
     * Return a passphrase for the given key. If no record has been found, return null.
     * Note: In case of an unprotected secret key, this method must may not return null, but a {@link Passphrase} with
     * a content of null.
     *
     * @param keyId if of the secret key
     * @return passphrase or null, if no passphrase record has been found.
     */
    @Nullable Passphrase getPassphraseFor(long keyId);

    boolean hasPassphrase(long keyId);
}
