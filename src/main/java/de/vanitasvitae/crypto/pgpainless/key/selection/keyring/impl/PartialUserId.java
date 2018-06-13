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
package de.vanitasvitae.crypto.pgpainless.key.selection.keyring.impl;

import java.util.Iterator;

import de.vanitasvitae.crypto.pgpainless.key.selection.key.PublicKeySelectionStrategy;
import de.vanitasvitae.crypto.pgpainless.key.selection.key.SecretKeySelectionStrategy;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

public class PartialUserId {

    public static class PubRingSelectionStrategy extends PublicKeySelectionStrategy<String> {

        @Override
        public boolean accept(String identifier, PGPPublicKey key) {
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
        public boolean accept(String identifier, PGPSecretKey key) {
            for (Iterator userIds = key.getUserIDs(); userIds.hasNext(); ) {
                String userId = (String) userIds.next();
                if (userId.contains(identifier)) {
                    return true;
                }
            }
            return false;
        }
    }
}
