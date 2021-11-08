// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.signature.subpackets.SignatureSubpacketGeneratorWrapper;

public class KeySpec {

    private final KeyType keyType;
    private final SignatureSubpacketGeneratorWrapper subpacketGenerator;
    private final boolean inheritedSubPackets;

    KeySpec(@Nonnull KeyType type,
            @Nonnull PGPSignatureSubpacketGenerator subpacketGenerator,
            boolean inheritedSubPackets) {
        this(
                type,
                SignatureSubpacketGeneratorWrapper.createSubpacketsFrom(subpacketGenerator.generate()),
                inheritedSubPackets);
    }

    KeySpec(@Nonnull KeyType type,
            @Nonnull SignatureSubpacketGeneratorWrapper subpacketGenerator,
            boolean inheritedSubPackets) {
        this.keyType = type;
        this.subpacketGenerator = subpacketGenerator;
        this.inheritedSubPackets = inheritedSubPackets;
    }

    @Nonnull
    KeyType getKeyType() {
        return keyType;
    }

    @Nonnull
    public PGPSignatureSubpacketVector getSubpackets() {
        return subpacketGenerator.getGenerator().generate();
    }

    @Nonnull
    SignatureSubpacketGeneratorWrapper getSubpacketGenerator() {
        return subpacketGenerator;
    }

    boolean isInheritedSubPackets() {
        return inheritedSubPackets;
    }

    public static KeySpecBuilder getBuilder(KeyType type, KeyFlag flag, KeyFlag... flags) {
        return new KeySpecBuilder(type, flag, flags);
    }
}
