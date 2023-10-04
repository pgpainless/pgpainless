// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.provider

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Provider

class BouncyCastleProviderFactory : ProviderFactory() {
    override val securityProvider: Provider = BouncyCastleProvider()
}