package org.pgpainless.implementation;

public class ImplementationFactory {

    private static CryptoEngineImplementation FACTORY_IMPLEMENTATION = new BcCryptoEngineImplementation();

    public static void setFactoryImplementation(CryptoEngineImplementation implementation) {
        FACTORY_IMPLEMENTATION = implementation;
    }

    public static CryptoEngineImplementation getInstance() {
        return FACTORY_IMPLEMENTATION;
    }

}
