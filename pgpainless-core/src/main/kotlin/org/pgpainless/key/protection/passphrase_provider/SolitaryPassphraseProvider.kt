// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.protection.passphrase_provider

import org.bouncycastle.bcpg.KeyIdentifier
import org.pgpainless.util.Passphrase

/** Implementation of the [SecretKeyPassphraseProvider] that holds a single [Passphrase]. */
class SolitaryPassphraseProvider(val passphrase: Passphrase?) : SecretKeyPassphraseProvider {

    override fun getPassphraseFor(keyIdentifier: KeyIdentifier): Passphrase? = passphrase

    override fun hasPassphrase(keyIdentifier: KeyIdentifier): Boolean = true
}
