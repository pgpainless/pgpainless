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

    public static KeySpecBuilder getBuilder(KeyType type, KeyFlag... flags) {
        return new KeySpecBuilder(type, flags);
    }
}
