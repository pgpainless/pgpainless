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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPMarker;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.collection.PGPKeyRingCollection;
import org.pgpainless.util.ArmorUtils;

public class KeyRingReader {

    public static final Charset UTF8 = Charset.forName("UTF-8");

    public PGPPublicKeyRing publicKeyRing(@Nonnull InputStream inputStream) throws IOException {
        return readPublicKeyRing(inputStream);
    }

    public PGPPublicKeyRing publicKeyRing(@Nonnull byte[] bytes) throws IOException {
        return publicKeyRing(new ByteArrayInputStream(bytes));
    }

    public PGPPublicKeyRing publicKeyRing(@Nonnull String asciiArmored) throws IOException {
        return publicKeyRing(asciiArmored.getBytes(UTF8));
    }

    public PGPPublicKeyRingCollection publicKeyRingCollection(@Nonnull InputStream inputStream)
            throws IOException, PGPException {
        return readPublicKeyRingCollection(inputStream);
    }

    public PGPPublicKeyRingCollection publicKeyRingCollection(@Nonnull byte[] bytes) throws IOException, PGPException {
        return publicKeyRingCollection(new ByteArrayInputStream(bytes));
    }

    public PGPPublicKeyRingCollection publicKeyRingCollection(@Nonnull String asciiArmored) throws IOException, PGPException {
        return publicKeyRingCollection(asciiArmored.getBytes(UTF8));
    }

    public PGPSecretKeyRing secretKeyRing(@Nonnull InputStream inputStream) throws IOException {
        return readSecretKeyRing(inputStream);
    }

    public PGPSecretKeyRing secretKeyRing(@Nonnull byte[] bytes) throws IOException {
        return secretKeyRing(new ByteArrayInputStream(bytes));
    }

    public PGPSecretKeyRing secretKeyRing(@Nonnull String asciiArmored) throws IOException {
        return secretKeyRing(asciiArmored.getBytes(UTF8));
    }

    public PGPSecretKeyRingCollection secretKeyRingCollection(@Nonnull InputStream inputStream)
            throws IOException, PGPException {
        return readSecretKeyRingCollection(inputStream);
    }

    public PGPSecretKeyRingCollection secretKeyRingCollection(@Nonnull byte[] bytes) throws IOException, PGPException {
        return secretKeyRingCollection(new ByteArrayInputStream(bytes));
    }

    public PGPSecretKeyRingCollection secretKeyRingCollection(@Nonnull String asciiArmored) throws IOException, PGPException {
        return secretKeyRingCollection(asciiArmored.getBytes(UTF8));
    }

    public PGPKeyRingCollection keyRingCollection(@Nonnull InputStream inputStream, boolean isSilent)
            throws IOException, PGPException {
        return readKeyRingCollection(inputStream, isSilent);
    }

    public PGPKeyRingCollection keyRingCollection(@Nonnull byte[] bytes, boolean isSilent) throws IOException, PGPException {
        return keyRingCollection(new ByteArrayInputStream(bytes), isSilent);
    }

    public PGPKeyRingCollection keyRingCollection(@Nonnull String asciiArmored, boolean isSilent) throws IOException, PGPException {
        return keyRingCollection(asciiArmored.getBytes(UTF8), isSilent);
    }

    public static PGPPublicKeyRing readPublicKeyRing(@Nonnull InputStream inputStream) throws IOException {
        PGPObjectFactory objectFactory = new PGPObjectFactory(
                ArmorUtils.getDecoderStream(inputStream),
                ImplementationFactory.getInstance().getKeyFingerprintCalculator());
        Object next;
        do {
            next = objectFactory.nextObject();
            if (next == null) {
                return null;
            }
            if (next instanceof PGPMarker) {
                continue;
            }
            if (next instanceof PGPPublicKeyRing) {
                return (PGPPublicKeyRing) next;
            }
        } while (true);
    }

    public static PGPPublicKeyRingCollection readPublicKeyRingCollection(@Nonnull InputStream inputStream)
            throws IOException, PGPException {
        PGPObjectFactory objectFactory = new PGPObjectFactory(
                ArmorUtils.getDecoderStream(inputStream),
                ImplementationFactory.getInstance().getKeyFingerprintCalculator());

        List<PGPPublicKeyRing> rings = new ArrayList<>();

        Object next;
        do {
            next = objectFactory.nextObject();
            if (next == null) {
                return new PGPPublicKeyRingCollection(rings);
            }
            if (next instanceof PGPMarker) {
                continue;
            }
            if (next instanceof PGPPublicKeyRing) {
                rings.add((PGPPublicKeyRing) next);
            }
            if (next instanceof PGPPublicKeyRingCollection) {
                PGPPublicKeyRingCollection collection = (PGPPublicKeyRingCollection) next;
                Iterator<PGPPublicKeyRing> iterator = collection.getKeyRings();
                while (iterator.hasNext()) {
                    rings.add(iterator.next());
                }
            }
        } while (true);
    }

    public static PGPSecretKeyRing readSecretKeyRing(@Nonnull InputStream inputStream) throws IOException {
        InputStream decoderStream = ArmorUtils.getDecoderStream(inputStream);
        PGPObjectFactory objectFactory = new PGPObjectFactory(
                decoderStream,
                ImplementationFactory.getInstance().getKeyFingerprintCalculator());

        Object next;
        do {
            next = objectFactory.nextObject();
            if (next == null) {
                return null;
            }
            if (next instanceof PGPMarker) {
                continue;
            }
            if (next instanceof PGPSecretKeyRing) {
                Streams.drain(decoderStream);
                return (PGPSecretKeyRing) next;
            }
        } while (true);
    }

    public static PGPSecretKeyRingCollection readSecretKeyRingCollection(@Nonnull InputStream inputStream)
            throws IOException, PGPException {
        PGPObjectFactory objectFactory = new PGPObjectFactory(
                ArmorUtils.getDecoderStream(inputStream),
                ImplementationFactory.getInstance().getKeyFingerprintCalculator());

        List<PGPSecretKeyRing> rings = new ArrayList<>();

        Object next;
        do {
            next = objectFactory.nextObject();
            if (next == null) {
                return new PGPSecretKeyRingCollection(rings);
            }
            if (next instanceof PGPMarker) {
                continue;
            }
            if (next instanceof PGPSecretKeyRing) {
                rings.add((PGPSecretKeyRing) next);
            }
            if (next instanceof PGPSecretKeyRingCollection) {
                PGPSecretKeyRingCollection collection = (PGPSecretKeyRingCollection) next;
                Iterator<PGPSecretKeyRing> iterator = collection.getKeyRings();
                while (iterator.hasNext()) {
                    rings.add(iterator.next());
                }
            }
        } while (true);
    }

    public static PGPKeyRingCollection readKeyRingCollection(@Nonnull InputStream inputStream, boolean isSilent)
            throws IOException, PGPException {
        return new PGPKeyRingCollection(inputStream, isSilent);
    }
}
