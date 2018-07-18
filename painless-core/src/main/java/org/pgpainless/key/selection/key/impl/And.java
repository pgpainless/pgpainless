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
package org.pgpainless.key.selection.key.impl;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.pgpainless.key.selection.key.PublicKeySelectionStrategy;
import org.pgpainless.key.selection.key.SecretKeySelectionStrategy;

public class And {

    public static class PubKeySelectionStrategy<O> extends PublicKeySelectionStrategy<O> {

        private final PublicKeySelectionStrategy<O> left;
        private final PublicKeySelectionStrategy<O> right;

        public PubKeySelectionStrategy(PublicKeySelectionStrategy<O> left,
                                       PublicKeySelectionStrategy<O> right) {
            this.left = left;
            this.right = right;
        }

        @Override
        public boolean accept(O identifier, PGPPublicKey key) {
            return left.accept(identifier, key) && right.accept(identifier, key);
        }
    }

    public static class SecKeySelectionStrategy<O> extends SecretKeySelectionStrategy<O> {

        private final SecretKeySelectionStrategy<O> left;
        private final SecretKeySelectionStrategy<O> right;

        public SecKeySelectionStrategy(SecretKeySelectionStrategy<O> left,
                                       SecretKeySelectionStrategy<O> right) {
            this.left = left;
            this.right = right;
        }

        @Override
        public boolean accept(O identifier, PGPSecretKey key) {
            return left.accept(identifier, key) && right.accept(identifier, key);
        }
    }

}
