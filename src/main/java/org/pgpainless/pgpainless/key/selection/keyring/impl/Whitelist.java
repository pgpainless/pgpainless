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
package org.pgpainless.pgpainless.key.selection.keyring.impl;

import java.util.Map;
import java.util.Set;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.pgpainless.key.selection.keyring.PublicKeyRingSelectionStrategy;
import org.pgpainless.pgpainless.key.selection.keyring.SecretKeyRingSelectionStrategy;
import org.pgpainless.pgpainless.util.MultiMap;

public class Whitelist {

    public static class PubRingSelectionStrategy<O> extends PublicKeyRingSelectionStrategy<O> {

        private final MultiMap<O, Long> whitelist;

        public PubRingSelectionStrategy(MultiMap<O, Long> whitelist) {
            this.whitelist = whitelist;
        }

        public PubRingSelectionStrategy(Map<O, Set<Long>> whitelist) {
            this.whitelist = new MultiMap<>(whitelist);
        }

        @Override
        public boolean accept(O identifier, PGPPublicKeyRing keyRing) {
            Set<Long> whitelistedKeyIds = whitelist.get(identifier);

            if (whitelistedKeyIds == null) {
                return false;
            }

            return whitelistedKeyIds.contains(keyRing.getPublicKey().getKeyID());
        }
    }

    public static class SecRingSelectionStrategy<O> extends SecretKeyRingSelectionStrategy<O> {

        private final MultiMap<O, Long> whitelist;

        public SecRingSelectionStrategy(MultiMap<O, Long> whitelist) {
            this.whitelist = whitelist;
        }

        public SecRingSelectionStrategy(Map<O, Set<Long>> whitelist) {
            this.whitelist = new MultiMap<>(whitelist);
        }

        @Override
        public boolean accept(O identifier, PGPSecretKeyRing keyRing) {
            Set<Long> whitelistedKeyIds = whitelist.get(identifier);

            if (whitelistedKeyIds == null) {
                return false;
            }

            return whitelistedKeyIds.contains(keyRing.getPublicKey().getKeyID());
        }

    }
}