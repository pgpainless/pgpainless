// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

public enum MissingKeyPassphraseStrategy {
    INTERACTIVE, // ask for missing key passphrases one by one
    THROW_EXCEPTION // throw an exception with all keys with missing passphrases
}
