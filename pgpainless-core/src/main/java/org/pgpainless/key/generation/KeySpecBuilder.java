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

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.AlgorithmSuite;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.Feature;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.util.CollectionUtils;

public class KeySpecBuilder implements KeySpecBuilderInterface {

    private final KeyType type;
    private final KeyFlag[] keyFlags;
    private final PGPSignatureSubpacketGenerator hashedSubPackets = new PGPSignatureSubpacketGenerator();
    private final AlgorithmSuite algorithmSuite = PGPainless.getPolicy().getKeyGenerationAlgorithmSuite();
    private Set<CompressionAlgorithm> preferredCompressionAlgorithms = algorithmSuite.getCompressionAlgorithms();
    private Set<HashAlgorithm> preferredHashAlgorithms = algorithmSuite.getHashAlgorithms();
    private Set<SymmetricKeyAlgorithm> preferredSymmetricAlgorithms = algorithmSuite.getSymmetricKeyAlgorithms();

    KeySpecBuilder(@Nonnull KeyType type, KeyFlag flag, KeyFlag... flags) {
        if (flag == null) {
            throw new IllegalArgumentException("Key MUST carry at least one key flag");
        }
        if (flags == null) {
            throw new IllegalArgumentException("List of additional flags MUST NOT be null.");
        }
        flags = CollectionUtils.concat(flag, flags);
        assureKeyCanCarryFlags(type, flags);
        this.type = type;
        this.keyFlags = flags;
    }

    @Override
    public KeySpecBuilder overridePreferredCompressionAlgorithms(@Nonnull CompressionAlgorithm... compressionAlgorithms) {
        this.preferredCompressionAlgorithms = new LinkedHashSet<>(Arrays.asList(compressionAlgorithms));
        return this;
    }

    @Override
    public KeySpecBuilder overridePreferredHashAlgorithms(@Nonnull HashAlgorithm... preferredHashAlgorithms) {
        this.preferredHashAlgorithms = new LinkedHashSet<>(Arrays.asList(preferredHashAlgorithms));
        return this;
    }

    @Override
    public KeySpecBuilder overridePreferredSymmetricKeyAlgorithms(@Nonnull SymmetricKeyAlgorithm... preferredSymmetricKeyAlgorithms) {
        this.preferredSymmetricAlgorithms = new LinkedHashSet<>(Arrays.asList(preferredSymmetricKeyAlgorithms));
        return this;
    }


    @Override
    public KeySpec build() {
        this.hashedSubPackets.setKeyFlags(false, KeyFlag.toBitmask(keyFlags));
        this.hashedSubPackets.setPreferredCompressionAlgorithms(false, getPreferredCompressionAlgorithmIDs());
        this.hashedSubPackets.setPreferredHashAlgorithms(false, getPreferredHashAlgorithmIDs());
        this.hashedSubPackets.setPreferredSymmetricAlgorithms(false, getPreferredSymmetricKeyAlgorithmIDs());
        this.hashedSubPackets.setFeature(false, Feature.MODIFICATION_DETECTION.getFeatureId());

        return new KeySpec(type, hashedSubPackets, false);
    }

    private int[] getPreferredCompressionAlgorithmIDs() {
        int[] ids = new int[preferredCompressionAlgorithms.size()];
        Iterator<CompressionAlgorithm> iterator = preferredCompressionAlgorithms.iterator();
        for (int i = 0; i < ids.length; i++) {
            ids[i] = iterator.next().getAlgorithmId();
        }
        return ids;
    }

    private int[] getPreferredHashAlgorithmIDs() {
        int[] ids = new int[preferredHashAlgorithms.size()];
        Iterator<HashAlgorithm> iterator = preferredHashAlgorithms.iterator();
        for (int i = 0; i < ids.length; i++) {
            ids[i] = iterator.next().getAlgorithmId();
        }
        return ids;
    }

    private int[] getPreferredSymmetricKeyAlgorithmIDs() {
        int[] ids = new int[preferredSymmetricAlgorithms.size()];
        Iterator<SymmetricKeyAlgorithm> iterator = preferredSymmetricAlgorithms.iterator();
        for (int i = 0; i < ids.length; i++) {
            ids[i] = iterator.next().getAlgorithmId();
        }
        return ids;
    }

    private static void assureKeyCanCarryFlags(KeyType type, KeyFlag... flags) {
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
}
