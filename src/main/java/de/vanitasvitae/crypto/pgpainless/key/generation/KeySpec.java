package de.vanitasvitae.crypto.pgpainless.key.generation;

import java.util.Set;

import de.vanitasvitae.crypto.pgpainless.key.algorithm.AlgorithmSuite;
import de.vanitasvitae.crypto.pgpainless.key.algorithm.Feature;
import de.vanitasvitae.crypto.pgpainless.key.generation.type.KeyType;

public class KeySpec {

    private final KeyType keyType;
    private final int keyFlags;
    private final AlgorithmSuite algorithmSuite;
    private final Set<Feature> features;

    KeySpec(KeyType type,
                   int keyFlags,
                   AlgorithmSuite preferredAlgorithms,
                   Set<Feature> features) {
        this.keyType = type;
        this.keyFlags = keyFlags;
        this.algorithmSuite = preferredAlgorithms;
        this.features = features;
    }

    KeyType getKeyType() {
        return keyType;
    }

    int getKeyFlags() {
        return keyFlags;
    }

    AlgorithmSuite getPreferredAlgorithms() {
        return algorithmSuite;
    }

    byte getFeatures() {
        byte val = 0;
        for (Feature f : features) {
            val |= f.getFeatureId();
        }
        return val;
    }

    public static KeySpecBuilder getBuilder() {
        return new KeySpecBuilder();
    }
}
