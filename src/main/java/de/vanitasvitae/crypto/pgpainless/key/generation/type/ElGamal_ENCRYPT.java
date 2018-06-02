package de.vanitasvitae.crypto.pgpainless.key.generation.type;

import de.vanitasvitae.crypto.pgpainless.key.algorithm.PublicKeyAlgorithm;

public enum ElGamal_ENCRYPT implements KeyType {

    _1024(1024),
    _2048(2048),
    _3072(3072),
    ;

    private final int length;

    ElGamal_ENCRYPT(int length) {
        this.length = length;
    }

    @Override
    public int getLength() {
        return length;
    }

    @Override
    public String getName() {
        return "ElGamal";
    }

    @Override
    public PublicKeyAlgorithm getAlgorithm() {
        return PublicKeyAlgorithm.ELGAMAL_ENCRYPT;
    }
}
