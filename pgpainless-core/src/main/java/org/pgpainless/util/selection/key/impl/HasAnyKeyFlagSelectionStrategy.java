/*
 * Copyright 2021 Paul Schaub.
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
package org.pgpainless.util.selection.key.impl;

import java.util.Iterator;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.util.selection.key.PublicKeySelectionStrategy;
import org.pgpainless.util.selection.key.SecretKeySelectionStrategy;

/**
 * Selection Strategies that accept a key if it carries at least one of the given key flags.
 */
public class HasAnyKeyFlagSelectionStrategy {

    public static class PublicKey extends PublicKeySelectionStrategy {

        private final int keyFlagMask;

        public PublicKey(KeyFlag... flags) {
            this(KeyFlag.toBitmask(flags));
        }

        public PublicKey(int mask) {
            this.keyFlagMask = mask;
        }

        @Override
        public boolean accept(PGPPublicKey key) {
            Iterator<PGPSignature> signatures = key.getSignatures();
            int flags = 0;
            while (signatures.hasNext()) {
                flags = signatures.next().getHashedSubPackets().getKeyFlags();
            }
            return (keyFlagMask & flags) != 0;
        }
    }

    public static class SecretKey extends SecretKeySelectionStrategy {

        private final int keyFlagMask;

        public SecretKey(KeyFlag... flags) {
            this(KeyFlag.toBitmask(flags));
        }

        public SecretKey(int mask) {
            this.keyFlagMask = mask;
        }

        @Override
        public boolean accept(PGPSecretKey key) {
            Iterator<PGPSignature> signatures = key.getPublicKey().getSignatures();
            int flags = signatures.next().getHashedSubPackets().getKeyFlags();
            return (keyFlagMask & flags) != 0;
        }
    }
}
