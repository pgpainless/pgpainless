// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.provider

import java.security.Provider
import org.bouncycastle.jce.provider.BouncyCastleProvider

class BouncyCastleProviderFactory : ProviderFactory() {
    override val securityProvider: Provider = BouncyCastleProvider()
}
