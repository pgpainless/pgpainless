// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.pgpainless.key.SubkeyIdentifier;

/**
 * Custom {@link PublicKeyDataDecryptorFactory} which can enable customized implementations of message decryption
 * using public keys.
 * This class can for example be used to implement message encryption using hardware tokens like smartcards or
 * TPMs.
 * @see ConsumerOptions#addCustomDecryptorFactory(CustomPublicKeyDataDecryptorFactory)
 */
public interface CustomPublicKeyDataDecryptorFactory extends PublicKeyDataDecryptorFactory {

    /**
     * Return the {@link SubkeyIdentifier} for which this particular {@link CustomPublicKeyDataDecryptorFactory}
     * is intended.
     *
     * @return subkey identifier
     */
    SubkeyIdentifier getSubkeyIdentifier();

}
