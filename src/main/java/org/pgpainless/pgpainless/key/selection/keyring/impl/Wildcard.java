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

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.pgpainless.key.selection.keyring.PublicKeyRingSelectionStrategy;
import org.pgpainless.pgpainless.key.selection.keyring.SecretKeyRingSelectionStrategy;

public class Wildcard {

    public class PubRingSelectionStrategy<O> extends PublicKeyRingSelectionStrategy<O> {

        @Override
        public boolean accept(O identifier, PGPPublicKeyRing keyRing) {
            return true;
        }
    }

    public class SecRingSelectionStrategy<O> extends SecretKeyRingSelectionStrategy<O> {

        @Override
        public boolean accept(O identifier, PGPSecretKeyRing keyRing) {
            return true;
        }
    }
}
