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
package org.pgpainless.key.selection.keyring.impl;

import java.util.Iterator;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.key.selection.keyring.PublicKeyRingSelectionStrategy;
import org.pgpainless.key.selection.keyring.SecretKeyRingSelectionStrategy;
import org.pgpainless.key.selection.keyring.PublicKeyRingSelectionStrategy;

public class ExactUserId {

    public static class PubRingSelectionStrategy extends PublicKeyRingSelectionStrategy<String> {

        @Override
        public boolean accept(String identifier, PGPPublicKeyRing keyRing) {
            Iterator<String> userIds = keyRing.getPublicKey().getUserIDs();
            while (userIds.hasNext()) {
                if (userIds.next().equals(identifier)) return true;
            }
            return false;
        }
    }

    public static class SecRingSelectionStrategy extends SecretKeyRingSelectionStrategy<String> {

        @Override
        public boolean accept(String identifier, PGPSecretKeyRing keyRing) {
            Iterator<String> userIds = keyRing.getPublicKey().getUserIDs();
            while (userIds.hasNext()) {
                if (userIds.next().equals(identifier)) return true;
            }
            return false;
        }
    }
}
