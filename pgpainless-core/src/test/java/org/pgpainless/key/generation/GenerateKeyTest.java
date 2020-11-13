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
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;

import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.collection.PGPKeyRing;

public class GenerateKeyTest {

    private static final Logger LOGGER = Logger.getLogger(GenerateKeyTest.class.getName());

    @Test
    public void generateKey() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {
        PGPKeyRing keyRing = PGPainless.generateKeyRing().simpleEcKeyRing("fresh@encrypted.key", "password123");

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        ArmoredOutputStream armor = new ArmoredOutputStream(bytes);
        keyRing.getPublicKeys().encode(armor);
        armor.close();
        String publicKey = new String(bytes.toByteArray());

        bytes = new ByteArrayOutputStream();
        armor = new ArmoredOutputStream(bytes);
        keyRing.getSecretKeys().encode(armor);
        armor.close();
        String privateKey = new String(bytes.toByteArray());

        LOGGER.log(Level.INFO, String.format("Generated random fresh EC key ring.\n" +
                "User-ID: %s\n" +
                "Fingerprint: %s\n" +
                "Key-ID: %s\n" +
                "%s\n" +
                "%s\n", keyRing.getPublicKeys().getPublicKey().getUserIDs().next(),
                new OpenPgpV4Fingerprint(keyRing.getPublicKeys()),
                keyRing.getPublicKeys().getPublicKey().getKeyID(),
                publicKey, privateKey));
    }
}
