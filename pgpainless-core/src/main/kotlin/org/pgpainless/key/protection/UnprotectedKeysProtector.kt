// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0
package org.pgpainless.key.protection

/**
 * Implementation of the [SecretKeyRingProtector] which assumes that all handled keys are not
 * password protected.
 */
class UnprotectedKeysProtector : SecretKeyRingProtector {
    override fun hasPassphraseFor(keyId: Long) = true

    override fun getDecryptor(keyId: Long) = null

    override fun getEncryptor(keyId: Long) = null
}
