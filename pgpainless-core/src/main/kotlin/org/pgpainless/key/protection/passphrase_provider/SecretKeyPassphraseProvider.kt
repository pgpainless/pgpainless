// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection.passphrase_provider

import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.PGPSecretKey
import org.pgpainless.util.Passphrase

/** Interface to allow the user to provide a [Passphrase] for an encrypted OpenPGP secret key. */
interface SecretKeyPassphraseProvider {

    /**
     * Return a passphrase for the given secret key. If no record is found, return null. Note: In
     * case of an unprotected secret key, this method must may not return null, but a [Passphrase]
     * with a content of null.
     *
     * @param secretKey secret key
     * @return passphrase or null, if no passphrase record is found.
     */
    fun getPassphraseFor(secretKey: PGPSecretKey): Passphrase? {
        return getPassphraseFor(secretKey.keyIdentifier)
    }

    /**
     * Return a passphrase for the given key. If no record has been found, return null. Note: In
     * case of an unprotected secret key, this method must may not return null, but a [Passphrase]
     * with a content of null.
     *
     * @param keyId if of the secret key
     * @return passphrase or null, if no passphrase record has been found.
     */
    @Deprecated("Pass in a KeyIdentifier instead.")
    fun getPassphraseFor(keyId: Long): Passphrase? = getPassphraseFor(KeyIdentifier(keyId))

    fun getPassphraseFor(keyIdentifier: KeyIdentifier): Passphrase?

    @Deprecated("Pass in a KeyIdentifier instead.")
    fun hasPassphrase(keyId: Long): Boolean = hasPassphrase(KeyIdentifier(keyId))

    fun hasPassphrase(keyIdentifier: KeyIdentifier): Boolean
}
