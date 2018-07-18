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

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

public class Email {

    public static class PubRingSelectionStrategy extends PartialUserId.PubRingSelectionStrategy {

        @Override
        public boolean accept(String email, PGPPublicKey key) {
            // Ensure, that email address is encapsulated in "<",">"
            if (!email.matches("^<.+>$")) {
                email = "<" + email + ">";
            }
            return super.accept(email, key);
        }
    }

    public static class SecRingSelectionStrategy extends PartialUserId.SecRingSelectionStrategy {

        @Override
        public boolean accept(String email, PGPSecretKey key) {
            // Ensure, that email address is encapsulated in "<",">"
            if (!email.matches("^<.+>$")) {
                email = "<" + email + ">";
            }
            return super.accept(email, key);
        }
    }
}
