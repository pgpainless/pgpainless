// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification

/**
 * Strategy defining how missing secret key passphrases are handled.
 */
enum class MissingKeyPassphraseStrategy {
    /**
     * Try to interactively obtain key passphrases one-by-one via callbacks,
     * eg [org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider].
     */
    INTERACTIVE,

    /**
     * Do not try to obtain passphrases interactively and instead throw a
     * [org.pgpainless.exception.MissingPassphraseException] listing all keys with missing passphrases.
     */
    THROW_EXCEPTION
}