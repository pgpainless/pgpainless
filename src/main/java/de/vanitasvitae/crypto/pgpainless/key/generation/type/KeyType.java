package de.vanitasvitae.crypto.pgpainless.key.generation.type;

import de.vanitasvitae.crypto.pgpainless.key.algorithm.PublicKeyAlgorithm;

public interface KeyType {

    int getLength();

    String getName();

    PublicKeyAlgorithm getAlgorithm();
}
