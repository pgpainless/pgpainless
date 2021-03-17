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
package org.pgpainless.key.parsing;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.util.KeyRingUtils;

import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class KeyRingReaderTest {
    @Test
    void publicKeyRingCollectionFromArmoredStream() throws IOException, PGPException {
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream("pub_keys_10_pieces.asc");
        ArmoredInputStream armoredInputStream = new ArmoredInputStream(inputStream);
        PGPPublicKeyRingCollection rings = PGPainless.readKeyRing().publicKeyRingCollection(armoredInputStream);
        assertEquals(rings.size(), 10);
    }

    @Test
    void publicKeyRingCollectionFromNotArmoredStream() throws IOException, PGPException,
            InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        Collection<PGPPublicKeyRing> collection = new ArrayList<>();

        for (int i = 0; i < 10; i++) {
            PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().simpleEcKeyRing("user_" + i + "@encrypted.key");
            collection.add(KeyRingUtils.publicKeyRingFrom(secretKeys));
        }

        PGPPublicKeyRingCollection originalRings = new PGPPublicKeyRingCollection(collection);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        originalRings.encode(out);

        ByteArrayInputStream inputStream = new ByteArrayInputStream(out.toByteArray());
        PGPPublicKeyRingCollection parsedRings = PGPainless.readKeyRing().publicKeyRingCollection(inputStream);
        assertEquals(parsedRings.size(), 10);
    }

    @Test
    void publicKeyRingCollectionFromString() throws IOException, PGPException, URISyntaxException {
        URL resource = getClass().getClassLoader().getResource("pub_keys_10_pieces.asc");
        String armoredString = new String(Files.readAllBytes(new File(resource.toURI()).toPath()));
        InputStream inputStream = new ByteArrayInputStream(armoredString.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream armoredInputStream = new ArmoredInputStream(inputStream);
        PGPPublicKeyRingCollection rings = PGPainless.readKeyRing().publicKeyRingCollection(armoredInputStream);
        assertEquals(rings.size(), 10);
    }

    @Test
    void publicKeyRingCollectionFromStringFailed() throws IOException, PGPException, URISyntaxException {
        URL resource = getClass().getClassLoader().getResource("pub_keys_10_pieces.asc");
        String armoredString = new String(Files.readAllBytes(new File(resource.toURI()).toPath()));
        PGPPublicKeyRingCollection rings = PGPainless.readKeyRing().publicKeyRingCollection(armoredString);
        assertNotEquals(rings.size(), 10);
    }

    @Test
    void publicKeyRingCollectionFromBytes() throws IOException, PGPException, URISyntaxException {
        URL resource = getClass().getClassLoader().getResource("pub_keys_10_pieces.asc");
        byte[] bytes = Files.readAllBytes(new File(resource.toURI()).toPath());
        InputStream armoredInputStream = new ArmoredInputStream(new ByteArrayInputStream(bytes));
        PGPPublicKeyRingCollection rings = PGPainless.readKeyRing().publicKeyRingCollection(armoredInputStream);
        assertEquals(rings.size(), 10);
    }

    @Test
    void publicKeyRingCollectionFromBytesFailed() throws IOException, PGPException, URISyntaxException {
        URL resource = getClass().getClassLoader().getResource("pub_keys_10_pieces.asc");
        byte[] bytes = Files.readAllBytes(new File(resource.toURI()).toPath());
        PGPPublicKeyRingCollection rings = PGPainless.readKeyRing().publicKeyRingCollection(bytes);
        assertNotEquals(rings.size(), 10);
    }
}