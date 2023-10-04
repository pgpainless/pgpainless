// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.provider

import java.security.Provider

/**
 * Allow the use of different [Provider] implementations to provide cryptographic primitives by setting
 * a [ProviderFactory] singleton.
 * By default, the class is initialized with a [BouncyCastleProviderFactory].
 * To make use of your own custom [Provider], call [setFactory], passing your
 * own custom [ProviderFactory] instance.
 */
abstract class ProviderFactory {

    protected abstract val securityProvider: Provider
    protected open val securityProviderName: String
        get() = securityProvider.name

    companion object {
        // singleton instance
        @JvmStatic
        var factory: ProviderFactory = BouncyCastleProviderFactory()

        @JvmStatic
        val provider: Provider
            @JvmName("getProvider")
            get() = factory.securityProvider

        @JvmStatic
        val providerName: String
            get() = factory.securityProviderName
    }
}