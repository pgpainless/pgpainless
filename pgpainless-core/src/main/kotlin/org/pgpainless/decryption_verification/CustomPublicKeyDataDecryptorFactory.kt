// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification

import org.bouncycastle.bcpg.KeyIdentifier
import org.bouncycastle.openpgp.operator.AbstractPublicKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory

/**
 * Custom [PublicKeyDataDecryptorFactory] which can enable customized implementations of message
 * decryption using public keys. This class can for example be used to implement message encryption
 * using hardware tokens like smartcards or TPMs.
 *
 * @see [ConsumerOptions.addCustomDecryptorFactory]
 */
abstract class CustomPublicKeyDataDecryptorFactory : AbstractPublicKeyDataDecryptorFactory() {

    /**
     * Identifier for the subkey for which this particular [CustomPublicKeyDataDecryptorFactory] is
     * intended.
     *
     * @return subkey identifier
     */
    abstract val keyIdentifier: KeyIdentifier
}
