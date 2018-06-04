package de.vanitasvitae.crypto.pgpainless.key.generation.type;

import java.security.spec.AlgorithmParameterSpec;

import de.vanitasvitae.crypto.pgpainless.algorithm.PublicKeyAlgorithm;
import de.vanitasvitae.crypto.pgpainless.key.generation.type.length.ElGamalLength;
import org.bouncycastle.jce.spec.ElGamalGenParameterSpec;

public class ElGamal_GENERAL implements KeyType {

    private final ElGamalLength length;

    ElGamal_GENERAL(ElGamalLength length) {
        this.length = length;
    }

    public static ElGamal_GENERAL withLength(ElGamalLength length) {
        return new ElGamal_GENERAL(length);
    }

    @Override
    public String getName() {
        return "ElGamal";
    }

    @Override
    public PublicKeyAlgorithm getAlgorithm() {
        return PublicKeyAlgorithm.ELGAMAL_GENERAL;
    }

    @Override
    public AlgorithmParameterSpec getAlgorithmSpec() {
        return new ElGamalGenParameterSpec(length.getLength());
    }
}
