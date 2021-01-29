/*
 * Copyright 2018 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.key.generation;

import javax.annotation.Nonnull;

import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.pgpainless.algorithm.AlgorithmSuite;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.Feature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.generation.type.KeyType;

public class KeySpecBuilder implements KeySpecBuilderInterface {

    private final KeyType type;
    private final PGPSignatureSubpacketGenerator hashedSubPackets = new PGPSignatureSubpacketGenerator();

    KeySpecBuilder(@Nonnull KeyType type) {
        this.type = type;
        hashedSubPackets.setPrimaryUserID(false, true);
    }

    @Override
    public WithDetailedConfiguration withKeyFlags(@Nonnull KeyFlag... flags) {
        assureKeyCanCarryFlags(flags);
        this.hashedSubPackets.setKeyFlags(false, KeyFlag.toBitmask(flags));
        return new WithDetailedConfigurationImpl();
    }

    private void assureKeyCanCarryFlags(KeyFlag... flags) {
        final int mask = KeyFlag.toBitmask(flags);

        if (!type.canCertify() && KeyFlag.hasKeyFlag(mask, KeyFlag.CERTIFY_OTHER)) {
            throw new IllegalArgumentException("KeyType " + type.getName() + " cannot carry key flag CERTIFY_OTHER.");
        }

        if (!type.canSign() && KeyFlag.hasKeyFlag(mask, KeyFlag.SIGN_DATA)) {
            throw new IllegalArgumentException("KeyType " + type.getName() + " cannot carry key flag SIGN_DATA.");
        }

        if (!type.canEncryptCommunication() && KeyFlag.hasKeyFlag(mask, KeyFlag.ENCRYPT_COMMS)) {
            throw new IllegalArgumentException("KeyType " + type.getName() + " cannot carry key flag ENCRYPT_COMMS.");
        }

        if (!type.canEncryptStorage() && KeyFlag.hasKeyFlag(mask, KeyFlag.ENCRYPT_STORAGE)) {
            throw new IllegalArgumentException("KeyType " + type.getName() + " cannot carry key flag ENCRYPT_STORAGE.");
        }

        if (!type.canAuthenticate() && KeyFlag.hasKeyFlag(mask, KeyFlag.AUTHENTICATION)) {
            throw new IllegalArgumentException("KeyType " + type.getName() + " cannot carry key flag AUTHENTIACTION.");
        }
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
        public WithPreferredHashAlgorithms withPreferredSymmetricAlgorithms(@Nonnull SymmetricKeyAlgorithm... algorithms) {
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
        public WithPreferredCompressionAlgorithms withPreferredHashAlgorithms(@Nonnull HashAlgorithm... algorithms) {
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
        public WithFeatures withPreferredCompressionAlgorithms(@Nonnull CompressionAlgorithm... algorithms) {
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
        public WithFeatures withFeature(@Nonnull Feature feature) {
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
