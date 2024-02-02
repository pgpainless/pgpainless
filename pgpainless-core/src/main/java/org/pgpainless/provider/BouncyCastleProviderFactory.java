// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.provider;

import java.security.Provider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Implementation of {@link ProviderFactory} using a {@link BouncyCastleProvider}.
 */
public final class BouncyCastleProviderFactory extends ProviderFactory {

    private static final Provider provider = new BouncyCastleProvider();

    @Override
    public Provider _getProvider() {
        return provider;
    }

}