package de.vanitasvitae.crypto.pgpainless.key.generation.type;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import de.vanitasvitae.crypto.pgpainless.key.algorithm.PublicKeyAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public enum DSA implements KeyType {

    _1024(1024),
    _2048(2048),
    _3072(3072),
    ;

    private final int length;

    DSA(int length) {
        this.length = length;
    }

    @Override
    public int getLength() {
        return length;
    }

    @Override
    public String getName() {
        return "DSA";
    }

    @Override
    public PublicKeyAlgorithm getAlgorithm() {
        return PublicKeyAlgorithm.DSA;
    }
}
