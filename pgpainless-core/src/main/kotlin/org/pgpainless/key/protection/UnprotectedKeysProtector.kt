// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0
package org.pgpainless.key.protection

import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor

/**
 * Implementation of the [SecretKeyRingProtector] which assumes that all handled keys are not
 * password protected.
 */
class UnprotectedKeysProtector : SecretKeyRingProtector {
    override fun hasPassphraseFor(keyIdentifier: KeyIdentifier): Boolean = true

    override fun getDecryptor(keyIdentifier: KeyIdentifier): PBESecretKeyDecryptor? = null

    override fun getEncryptor(keyIdentifier: KeyIdentifier): PBESecretKeyEncryptor? = null

    override fun getKeyPassword(p0: OpenPGPKey.OpenPGPSecretKey?): CharArray? = null
}
