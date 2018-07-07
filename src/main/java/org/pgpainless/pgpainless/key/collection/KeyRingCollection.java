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
package org.pgpainless.pgpainless.key.collection;

import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

public class KeyRingCollection {

    private static final Logger LOGGER = Logger.getLogger(KeyRingCollection.class.getName());

    private PGPPublicKeyRingCollection publicKeys;
    private PGPSecretKeyRingCollection secretKeys;

    public KeyRingCollection(PGPPublicKeyRingCollection publicKeyRings, PGPSecretKeyRingCollection secretKeyRings) {
        this.publicKeys = publicKeyRings;
        this.secretKeys = secretKeyRings;
    }

    public KeyRingCollection(PGPPublicKeyRingCollection publicKeyRings) {
        this(publicKeyRings, null);
    }

    public KeyRingCollection(PGPSecretKeyRingCollection secretKeyRings) {
        this(null, secretKeyRings);
    }

    public void importPublicKeys(PGPPublicKeyRingCollection publicKeyRings) {
        for (PGPPublicKeyRing keyRing : Objects.requireNonNull(publicKeyRings)) {
            try {
                this.publicKeys = PGPPublicKeyRingCollection.addPublicKeyRing(this.publicKeys, keyRing);
            } catch (IllegalArgumentException e) {
                // TODO: merge key rings.
                LOGGER.log(Level.FINE, "Keyring " + Long.toHexString(keyRing.getPublicKey().getKeyID()) +
                        " is already included in the collection. Skip!");
            }
        }
    }

    public void importSecretKeys(PGPSecretKeyRingCollection secretKeyRings) {
        for (PGPSecretKeyRing keyRing : Objects.requireNonNull(secretKeyRings)) {
            try {
                this.secretKeys = PGPSecretKeyRingCollection.addSecretKeyRing(this.secretKeys, keyRing);
            } catch (IllegalArgumentException e) {
                // TODO: merge key rings.
                LOGGER.log(Level.FINE, "Keyring " + Long.toHexString(keyRing.getPublicKey().getKeyID()) +
                        " is already included in the collection. Skip!");
            }
        }
    }
}
