// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.signature.subpackets.SignatureSubpackets;
import org.pgpainless.signature.subpackets.SignatureSubpacketsHelper;

import java.util.Date;

public class KeySpec {

    private final KeyType keyType;
    private final SignatureSubpackets subpacketGenerator;
    private final boolean inheritedSubPackets;
    private final Date keyCreationDate;

    KeySpec(@Nonnull KeyType type,
            @Nonnull SignatureSubpackets subpacketGenerator,
            boolean inheritedSubPackets,
            @Nullable Date keyCreationDate) {
        this.keyType = type;
        this.subpacketGenerator = subpacketGenerator;
        this.inheritedSubPackets = inheritedSubPackets;
        this.keyCreationDate = keyCreationDate;
    }

    @Nonnull
    public KeyType getKeyType() {
        return keyType;
    }

    @Nonnull
    public PGPSignatureSubpacketVector getSubpackets() {
        return SignatureSubpacketsHelper.toVector(subpacketGenerator);
    }

    @Nonnull
    public SignatureSubpackets getSubpacketGenerator() {
        return subpacketGenerator;
    }

    boolean isInheritedSubPackets() {
        return inheritedSubPackets;
    }

    @Nullable
    public Date getKeyCreationDate() {
        return keyCreationDate;
    }

    public static KeySpecBuilder getBuilder(KeyType type, KeyFlag flag, KeyFlag... flags) {
        return new KeySpecBuilder(type, flag, flags);
    }
}
