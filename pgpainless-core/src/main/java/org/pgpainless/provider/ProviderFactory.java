package org.pgpainless.provider;

import java.security.Provider;

public abstract class ProviderFactory {

    private static ProviderFactory FACTORY = new BouncyCastleProviderFactory();

    protected abstract Provider _getProvider();
    protected abstract String _getProviderName();

    public static void setFactory(ProviderFactory factory) {
        ProviderFactory.FACTORY = factory;
    }

    public static Provider getProvider() {
        return ProviderFactory.FACTORY._getProvider();
    }

    public static String getProviderName() {
        return ProviderFactory.FACTORY._getProviderName();
    }

}
