package de.vanitasvitae.crypto.pgpainless.key.generation.type;

import java.security.spec.AlgorithmParameterSpec;

import de.vanitasvitae.crypto.pgpainless.algorithm.PublicKeyAlgorithm;

public interface KeyType {

    String getName();

    PublicKeyAlgorithm getAlgorithm();

    AlgorithmParameterSpec getAlgorithmSpec();
}
