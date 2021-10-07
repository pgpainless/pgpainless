// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.provider;

import java.security.Provider;

public abstract class ProviderFactory {

    private static ProviderFactory FACTORY;

    protected abstract Provider _getProvider();
    protected abstract String _getProviderName();

    public static void setFactory(ProviderFactory factory) {
        ProviderFactory.FACTORY = factory;
    }

    public static ProviderFactory getFactory() {
        if (FACTORY == null) {
            FACTORY = new BouncyCastleProviderFactory();
        }
        return FACTORY;
    }

    public static Provider getProvider() {
        return ProviderFactory.getFactory()._getProvider();
    }

    public static String getProviderName() {
        return ProviderFactory.getFactory()._getProviderName();
    }

}
