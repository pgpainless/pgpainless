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
package org.pgpainless.key.collection;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.pgpainless.PGPainless;

public class KeyRingCollection {

    private static final Logger LOGGER = Logger.getLogger(KeyRingCollection.class.getName());

    private PGPPublicKeyRingCollection publicKeys;
    private PGPSecretKeyRingCollection secretKeys;

    public KeyRingCollection(PGPPublicKeyRingCollection publicKeyRings, PGPSecretKeyRingCollection secretKeyRings) {
        this.publicKeys = publicKeyRings;
        this.secretKeys = secretKeyRings;
    }

    public KeyRingCollection(File pubRingFile, File secRingFile) throws IOException, PGPException {
        if (pubRingFile != null) {
            InputStream pubRingIn = new FileInputStream(pubRingFile);
            this.publicKeys = PGPainless.readKeyRing().publicKeyRingCollection(pubRingIn);
            pubRingIn.close();
        }

        if (secRingFile != null) {
            InputStream secRingIn = new FileInputStream(secRingFile);
            this.secretKeys = PGPainless.readKeyRing().secretKeyRingCollection(secRingIn);
            secRingIn.close();
        }
    }

    public KeyRingCollection(PGPPublicKeyRingCollection publicKeyRings) {
        this(publicKeyRings, null);
    }

    public KeyRingCollection(PGPSecretKeyRingCollection secretKeyRings) {
        this(null, secretKeyRings);
    }

    public void importPublicKeys(PGPPublicKeyRingCollection publicKeyRings) {
        if (this.publicKeys == null) {
            this.publicKeys = publicKeyRings;
            return;
        }

        for (PGPPublicKeyRing keyRing : publicKeyRings) {
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
        if (this.secretKeys == null) {
            this.secretKeys = secretKeyRings;
            return;
        }

        for (PGPSecretKeyRing keyRing : secretKeyRings) {
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
