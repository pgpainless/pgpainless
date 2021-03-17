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
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.assertEquals;

class KeyRingReaderTest {
    @Test
    void publicKeyRingCollectionFromStream() throws IOException, PGPException {
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream("pub_keys_10_pieces.asc");
        ArmoredInputStream armoredInputStream = new ArmoredInputStream(inputStream);
        PGPPublicKeyRingCollection rings = PGPainless.readKeyRing().publicKeyRingCollection(armoredInputStream);
        assertEquals(rings.size(), 10);
    }

    @Test
    void publicKeyRingCollectionFromString() throws IOException, PGPException, URISyntaxException {
        URL resource = getClass().getClassLoader().getResource("pub_keys_10_pieces.asc");
        String armoredString = new String(Files.readAllBytes(new File(resource.toURI()).toPath()));
        ArmoredInputStream armoredInputStream = new ArmoredInputStream(new ByteArrayInputStream(armoredString.getBytes(StandardCharsets.UTF_8)));
        PGPPublicKeyRingCollection rings = PGPainless.readKeyRing().publicKeyRingCollection(armoredInputStream);
        assertEquals(rings.size(), 10);
    }

    @Test
    void publicKeyRingCollectionFromBytes() throws IOException, PGPException, URISyntaxException {
        URL resource = getClass().getClassLoader().getResource("pub_keys_10_pieces.asc");
        byte[] bytes =  Files.readAllBytes(new File(resource.toURI()).toPath());
        InputStream armoredInputStream = new ArmoredInputStream(new ByteArrayInputStream(bytes));
        PGPPublicKeyRingCollection rings = PGPainless.readKeyRing().publicKeyRingCollection(armoredInputStream);
        assertEquals(rings.size(), 10);
    }

    @Test
    void publicKeyRingCollectionFromBytesFailed() throws IOException, PGPException, URISyntaxException {
        URL resource = getClass().getClassLoader().getResource("pub_keys_10_pieces.asc");
        byte[] bytes = Files.readAllBytes(new File(resource.toURI()).toPath());
        PGPPublicKeyRingCollection rings = PGPainless.readKeyRing().publicKeyRingCollection(bytes);
        assertEquals(rings.size(), 10);
    }

    @Test
    void publicKeyRingCollectionFromStringFailed() throws IOException, PGPException, URISyntaxException {
        URL resource = getClass().getClassLoader().getResource("pub_keys_10_pieces.asc");
        String armoredString = new String(Files.readAllBytes(new File(resource.toURI()).toPath()));
        PGPPublicKeyRingCollection rings = PGPainless.readKeyRing().publicKeyRingCollection(armoredString);
        assertEquals(rings.size(), 10);
    }
}