// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection.passphrase_provider

import org.pgpainless.util.Passphrase

/**
 * Implementation of the [SecretKeyPassphraseProvider] that holds a map of key-IDs and respective [Passphrase].
 * It will return the right passphrase depending on the key-id.
 *
 * Note: This provider might return null!
 * TODO: Make this null-safe and throw an exception instead?
 */
class MapBasedPassphraseProvider(val map: Map<Long, Passphrase>) : SecretKeyPassphraseProvider {

    override fun getPassphraseFor(keyId: Long): Passphrase? = map[keyId]

    override fun hasPassphrase(keyId: Long): Boolean = map.containsKey(keyId)
}