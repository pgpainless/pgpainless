// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;

public interface CustomPublicKeyDataDecryptorFactory extends PublicKeyDataDecryptorFactory {

    long getKeyId();

}
