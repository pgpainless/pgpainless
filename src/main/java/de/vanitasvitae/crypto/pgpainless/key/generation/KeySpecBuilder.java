package de.vanitasvitae.crypto.pgpainless.key.generation;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import de.vanitasvitae.crypto.pgpainless.key.algorithm.AlgorithmSuite;
import de.vanitasvitae.crypto.pgpainless.key.algorithm.CompressionAlgorithm;
import de.vanitasvitae.crypto.pgpainless.key.algorithm.Feature;
import de.vanitasvitae.crypto.pgpainless.key.algorithm.HashAlgorithm;
import de.vanitasvitae.crypto.pgpainless.key.algorithm.KeyFlag;
import de.vanitasvitae.crypto.pgpainless.key.algorithm.SymmetricKeyAlgorithm;
import de.vanitasvitae.crypto.pgpainless.key.generation.type.KeyType;

public class KeySpecBuilder implements KeySpecBuilderInterface {

    private KeyType type;
    private int keyFlags;
    private AlgorithmSuite algorithmSuite = AlgorithmSuite.getDefaultAlgorithmSuite();
    private Set<Feature> features = new HashSet<>();

    @Override
    public WithKeyFlags ofType(KeyType type) {
        KeySpecBuilder.this.type = type;
        return new WithKeyFlagsImpl();
    }

    class WithKeyFlagsImpl implements WithKeyFlags {

        @Override
        public WithDetailedConfiguration withKeyFlags(KeyFlag... flags) {
            int val = 0;
            for (KeyFlag f : flags) {
                val |= f.getFlag();
            }
            KeySpecBuilder.this.keyFlags = val;
            return new WithDetailedConfigurationImpl();
        }

        @Override
        public WithDetailedConfiguration withDefaultKeyFlags() {
            return withKeyFlags(
                    KeyFlag.CERTIFY_OTHER,
                    KeyFlag.SIGN_DATA,
                    KeyFlag.ENCRYPT_COMMS,
                    KeyFlag.ENCRYPT_STORAGE,
                    KeyFlag.AUTHENTICATION);
        }
    }

    class WithDetailedConfigurationImpl implements WithDetailedConfiguration {

        @Deprecated
        @Override
        public WithPreferredSymmetricAlgorithms withDetailedConfiguration() {
            return new WithPreferredSymmetricAlgorithmsImpl();
        }

        @Override
        public KeySpec withStandardConfiguration() {
            return new KeySpec(
                    KeySpecBuilder.this.type,
                    KeySpecBuilder.this.keyFlags,
                    KeySpecBuilder.this.algorithmSuite,
                    KeySpecBuilder.this.features);
        }
    }

    class WithPreferredSymmetricAlgorithmsImpl implements WithPreferredSymmetricAlgorithms {

        @Override
        public WithPreferredHashAlgorithms withPreferredSymmetricAlgorithms(SymmetricKeyAlgorithm... algorithms) {
            KeySpecBuilder.this.algorithmSuite.setSymmetricKeyAlgorithms(Arrays.asList(algorithms));
            return new WithPreferredHashAlgorithmsImpl();
        }

        @Override
        public WithPreferredHashAlgorithms withDefaultSymmetricAlgorithms() {
            KeySpecBuilder.this.algorithmSuite.setSymmetricKeyAlgorithms(
                    AlgorithmSuite.getDefaultAlgorithmSuite().getSymmetricKeyAlgorithms());
            return new WithPreferredHashAlgorithmsImpl();
        }

        @Override
        public WithFeatures withDefaultAlgorithms() {
            KeySpecBuilder.this.algorithmSuite = AlgorithmSuite.getDefaultAlgorithmSuite();
            return new WithFeaturesImpl();
        }
    }

    class WithPreferredHashAlgorithmsImpl implements WithPreferredHashAlgorithms {

        @Override
        public WithPreferredCompressionAlgorithms withPreferredHashAlgorithms(HashAlgorithm... algorithms) {
            KeySpecBuilder.this.algorithmSuite.setHashAlgorithms(Arrays.asList(algorithms));
            return new WithPreferredCompressionAlgorithmsImpl();
        }

        @Override
        public WithPreferredCompressionAlgorithms withDefaultHashAlgorithms() {
            KeySpecBuilder.this.algorithmSuite.setHashAlgorithms(
                    AlgorithmSuite.getDefaultAlgorithmSuite().getHashAlgorithms());
            return new WithPreferredCompressionAlgorithmsImpl();
        }
    }

    class WithPreferredCompressionAlgorithmsImpl implements WithPreferredCompressionAlgorithms {

        @Override
        public WithFeatures withPreferredCompressionAlgorithms(CompressionAlgorithm... algorithms) {
            KeySpecBuilder.this.algorithmSuite.setCompressionAlgorithms(Arrays.asList(algorithms));
            return new WithFeaturesImpl();
        }

        @Override
        public WithFeatures withDefaultCompressionAlgorithms() {
            KeySpecBuilder.this.algorithmSuite.setCompressionAlgorithms(
                    AlgorithmSuite.getDefaultAlgorithmSuite().getCompressionAlgorithms());
            return new WithFeaturesImpl();
        }
    }

    class WithFeaturesImpl implements WithFeatures {

        @Override
        public WithFeatures withFeature(Feature feature) {
            KeySpecBuilder.this.features.add(feature);
            return this;
        }

        @Override
        public KeySpec done() {
            return new KeySpec(
                    KeySpecBuilder.this.type,
                    KeySpecBuilder.this.keyFlags,
                    KeySpecBuilder.this.algorithmSuite,
                    KeySpecBuilder.this.features);
        }
    }
}
