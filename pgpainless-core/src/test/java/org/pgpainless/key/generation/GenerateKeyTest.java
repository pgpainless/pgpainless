/*
 * Copyright 2020 Paul Schaub.
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
package org.pgpainless.key.generation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.junit.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.collection.PGPKeyRing;

public class GenerateKeyTest {

    @Test
    public void generateKey() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {
        PGPKeyRing keyRing = PGPainless.generateKeyRing().simpleEcKeyRing("cryptie@encrypted.key", "password123");

        print(keyRing.getPublicKeys().getPublicKey().getUserIDs().next());
        print(new OpenPgpV4Fingerprint(keyRing.getPublicKeys()));
        print(keyRing.getPublicKeys().getPublicKey().getKeyID());

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        ArmoredOutputStream armor = new ArmoredOutputStream(bytes);
        keyRing.getPublicKeys().encode(armor);
        armor.close();
        print(new String(bytes.toByteArray()));

        bytes = new ByteArrayOutputStream();
        armor = new ArmoredOutputStream(bytes);
        keyRing.getSecretKeys().encode(armor);
        armor.close();
        print(new String(bytes.toByteArray()));
    }

    public void print(Object obj) {
        // CHECKSTYLE:OFF
        System.out.println(obj);
        // CHECKSTYLE:ON
    }
}
