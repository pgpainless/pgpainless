// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

/**
 * Strategy defining how missing secret key passphrases are handled.
 */
public enum MissingKeyPassphraseStrategy {
    /**
     * Try to interactively obtain key passphrases one-by-one via callbacks,
     * eg {@link org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider}.
     */
    INTERACTIVE,
    /**
     * Do not try to obtain passphrases interactively and instead throw a
     * {@link org.pgpainless.exception.MissingPassphraseException} listing all keys with missing passphrases.
     */
    THROW_EXCEPTION
}
