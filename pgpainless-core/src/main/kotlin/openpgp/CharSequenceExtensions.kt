// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package openpgp

import org.pgpainless.util.Passphrase

/**
 * Extension function to convert a nullable [CharSequence] into an [Array]. Iff [this] is `null`,
 * then return an empty array, otherwise return an array only consisting of [this].
 *
 * @return array
 */
fun CharSequence?.toArray(): Array<CharSequence> = this?.let { arrayOf(it) } ?: emptyArray()

/**
 * Return a [Passphrase] from this [CharSequence]. Iff [this] is `null` or blank, then this method
 * returns [Passphrase.emptyPassphrase], otherwise it returns [Passphrase.fromPassword].
 *
 * @return passphrase
 */
fun CharSequence?.toPassphrase(): Passphrase =
    this?.let { Passphrase.fromPassword(it) } ?: Passphrase.emptyPassphrase()
