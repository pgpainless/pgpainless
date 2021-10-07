// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.type.KeyType;

public class KeySpec {

    private final KeyType keyType;
    private final PGPSignatureSubpacketGenerator subpacketGenerator;
    private final boolean inheritedSubPackets;

    KeySpec(@Nonnull KeyType type,
            @Nullable PGPSignatureSubpacketGenerator subpacketGenerator,
            boolean inheritedSubPackets) {
        this.keyType = type;
        this.subpacketGenerator = subpacketGenerator;
        this.inheritedSubPackets = inheritedSubPackets;
    }

    @Nonnull
    KeyType getKeyType() {
        return keyType;
    }

    @Nullable
    public PGPSignatureSubpacketVector getSubpackets() {
        return subpacketGenerator != null ? subpacketGenerator.generate() : null;
    }

    PGPSignatureSubpacketGenerator getSubpacketGenerator() {
        return subpacketGenerator;
    }

    boolean isInheritedSubPackets() {
        return inheritedSubPackets;
    }

    public static KeySpecBuilder getBuilder(KeyType type, KeyFlag flag, KeyFlag... flags) {
        return new KeySpecBuilder(type, flag, flags);
    }
}
