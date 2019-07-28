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

import javax.annotation.Nonnull;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.pgpainless.key.selection.key.PublicKeySelectionStrategy;
import org.pgpainless.key.selection.key.SecretKeySelectionStrategy;

public class PartialUserId {

    public static class PubRingSelectionStrategy extends PublicKeySelectionStrategy<String> {

        @Override
        public boolean accept(String identifier, @Nonnull PGPPublicKey key) {
            for (Iterator<String> userIds = key.getUserIDs(); userIds.hasNext(); ) {
                String userId = userIds.next();
                if (userId.contains(identifier)) {
                    return true;
                }
            }
            return false;
        }
    }

    public static class SecRingSelectionStrategy extends SecretKeySelectionStrategy<String> {

        @Override
        public boolean accept(String identifier, @Nonnull PGPSecretKey key) {
            for (Iterator<String> userIds = key.getUserIDs(); userIds.hasNext(); ) {
                String userId = userIds.next();
                if (userId.contains(identifier)) {
                    return true;
                }
            }
            return false;
        }
    }
}
