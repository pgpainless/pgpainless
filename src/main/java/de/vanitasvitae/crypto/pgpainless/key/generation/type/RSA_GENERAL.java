package de.vanitasvitae.crypto.pgpainless.key.generation.type;

import de.vanitasvitae.crypto.pgpainless.key.algorithm.PublicKeyAlgorithm;

public enum RSA_GENERAL implements KeyType {

    @Deprecated
    _1024(1024),
    @Deprecated
    _2048(2048),
    _3072(3072),
    _4096(4096),
    _8192(8192),
    ;

    private final int length;

    RSA_GENERAL(int length) {
        this.length = length;
    }

    @Override
    public int getLength() {
        return length;
    }

    @Override
    public String getName() {
        return "RSA";
    }

    @Override
    public PublicKeyAlgorithm getAlgorithm() {
        return PublicKeyAlgorithm.RSA_GENERAL;
    }
}
