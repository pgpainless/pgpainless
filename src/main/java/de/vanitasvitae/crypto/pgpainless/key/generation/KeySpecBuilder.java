package de.vanitasvitae.crypto.pgpainless.key.generation;

import de.vanitasvitae.crypto.pgpainless.algorithm.AlgorithmSuite;
import de.vanitasvitae.crypto.pgpainless.algorithm.CompressionAlgorithm;
import de.vanitasvitae.crypto.pgpainless.algorithm.Feature;
import de.vanitasvitae.crypto.pgpainless.algorithm.HashAlgorithm;
import de.vanitasvitae.crypto.pgpainless.algorithm.KeyFlag;
import de.vanitasvitae.crypto.pgpainless.algorithm.SymmetricKeyAlgorithm;
import de.vanitasvitae.crypto.pgpainless.key.generation.type.KeyType;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;

public class KeySpecBuilder implements KeySpecBuilderInterface {

    private KeyType type;
    private PGPSignatureSubpacketGenerator hashedSubPackets = new PGPSignatureSubpacketGenerator();

    KeySpecBuilder(KeyType type) {
        this.type = type;
    }

    @Override
    public WithDetailedConfiguration withKeyFlags(KeyFlag... flags) {
        int val = 0;
        for (KeyFlag f : flags) {
            val |= f.getFlag();
        }
        this.hashedSubPackets.setKeyFlags(false, val);
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

    @Override
    public KeySpec withInheritedSubPackets() {
        return new KeySpec(type, null, true);
    }

    class WithDetailedConfigurationImpl implements WithDetailedConfiguration {

        @Deprecated
        @Override
        public WithPreferredSymmetricAlgorithms withDetailedConfiguration() {
            return new WithPreferredSymmetricAlgorithmsImpl();
        }

        @Override
        public KeySpec withDefaultAlgorithms() {
            AlgorithmSuite defaultSuite = AlgorithmSuite.getDefaultAlgorithmSuite();
            hashedSubPackets.setPreferredCompressionAlgorithms(false, defaultSuite.getCompressionAlgorithmIds());
            hashedSubPackets.setPreferredSymmetricAlgorithms(false, defaultSuite.getSymmetricKeyAlgorithmIds());
            hashedSubPackets.setPreferredHashAlgorithms(false, defaultSuite.getHashAlgorithmIds());
            hashedSubPackets.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
            return new KeySpec(
                    KeySpecBuilder.this.type,
                    KeySpecBuilder.this.hashedSubPackets,
                    false);
        }
    }

    class WithPreferredSymmetricAlgorithmsImpl implements WithPreferredSymmetricAlgorithms {

        @Override
        public WithPreferredHashAlgorithms withPreferredSymmetricAlgorithms(SymmetricKeyAlgorithm... algorithms) {
            int[] ids = new int[algorithms.length];
            for (int i = 0; i < ids.length; i++) {
                ids[i] = algorithms[i].getAlgorithmId();
            }
            KeySpecBuilder.this.hashedSubPackets.setPreferredSymmetricAlgorithms(false, ids);
            return new WithPreferredHashAlgorithmsImpl();
        }

        @Override
        public WithPreferredHashAlgorithms withDefaultSymmetricAlgorithms() {
            KeySpecBuilder.this.hashedSubPackets.setPreferredSymmetricAlgorithms(false,
                    AlgorithmSuite.getDefaultAlgorithmSuite().getSymmetricKeyAlgorithmIds());
            return new WithPreferredHashAlgorithmsImpl();
        }

        @Override
        public WithFeatures withDefaultAlgorithms() {
            hashedSubPackets.setPreferredSymmetricAlgorithms(false,
                    AlgorithmSuite.getDefaultAlgorithmSuite().getSymmetricKeyAlgorithmIds());
            hashedSubPackets.setPreferredCompressionAlgorithms(false,
                    AlgorithmSuite.getDefaultAlgorithmSuite().getCompressionAlgorithmIds());
            hashedSubPackets.setPreferredHashAlgorithms(false,
                    AlgorithmSuite.getDefaultAlgorithmSuite().getHashAlgorithmIds());
            return new WithFeaturesImpl();
        }
    }

    class WithPreferredHashAlgorithmsImpl implements WithPreferredHashAlgorithms {

        @Override
        public WithPreferredCompressionAlgorithms withPreferredHashAlgorithms(HashAlgorithm... algorithms) {
            int[] ids = new int[algorithms.length];
            for (int i = 0; i < ids.length; i++) {
                ids[i] = algorithms[i].getAlgorithmId();
            }
            KeySpecBuilder.this.hashedSubPackets.setPreferredHashAlgorithms(false, ids);
            return new WithPreferredCompressionAlgorithmsImpl();
        }

        @Override
        public WithPreferredCompressionAlgorithms withDefaultHashAlgorithms() {
            KeySpecBuilder.this.hashedSubPackets.setPreferredHashAlgorithms(false,
                    AlgorithmSuite.getDefaultAlgorithmSuite().getHashAlgorithmIds());
            return new WithPreferredCompressionAlgorithmsImpl();
        }
    }

    class WithPreferredCompressionAlgorithmsImpl implements WithPreferredCompressionAlgorithms {

        @Override
        public WithFeatures withPreferredCompressionAlgorithms(CompressionAlgorithm... algorithms) {
            int[] ids = new int[algorithms.length];
            for (int i = 0; i < ids.length; i++) {
                ids[i] = algorithms[i].getAlgorithmId();
            }
            KeySpecBuilder.this.hashedSubPackets.setPreferredCompressionAlgorithms(false, ids);
            return new WithFeaturesImpl();
        }

        @Override
        public WithFeatures withDefaultCompressionAlgorithms() {
            KeySpecBuilder.this.hashedSubPackets.setPreferredCompressionAlgorithms(false,
                    AlgorithmSuite.getDefaultAlgorithmSuite().getCompressionAlgorithmIds());
            return new WithFeaturesImpl();
        }
    }

    class WithFeaturesImpl implements WithFeatures {

        @Override
        public WithFeatures withFeature(Feature feature) {
            KeySpecBuilder.this.hashedSubPackets.setFeature(false, feature.getFeatureId());
            return this;
        }

        @Override
        public KeySpec done() {
            return new KeySpec(
                    KeySpecBuilder.this.type,
                    hashedSubPackets,
                    false);
        }
    }
}
