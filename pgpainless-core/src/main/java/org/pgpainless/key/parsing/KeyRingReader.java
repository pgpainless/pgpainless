// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.parsing;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPMarker;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.collection.PGPKeyRingCollection;
import org.pgpainless.util.ArmorUtils;

public class KeyRingReader {

    public static final int MAX_ITERATIONS = 10000;

    @SuppressWarnings("CharsetObjectCanBeUsed")
    public static final Charset UTF8 = Charset.forName("UTF-8");

    /**
     * Read a {@link PGPKeyRing} (either {@link PGPSecretKeyRing} or {@link PGPPublicKeyRing}) from the given
     * {@link InputStream}.
     *
     * @param inputStream inputStream containing the OpenPGP key or certificate
     * @return key ring
     * @throws IOException in case of an IO error
     */
    @Nullable
    public PGPKeyRing keyRing(@Nonnull InputStream inputStream)
            throws IOException {
        return readKeyRing(inputStream);
    }

    /**
     * Read a {@link PGPKeyRing} (either {@link PGPSecretKeyRing} or {@link PGPPublicKeyRing}) from the given
     * byte array.
     *
     * @param bytes byte array containing the OpenPGP key or certificate
     * @return key ring
     * @throws IOException in case of an IO error
     */
    @Nullable
    public PGPKeyRing keyRing(@Nonnull byte[] bytes)
            throws IOException {
        return keyRing(new ByteArrayInputStream(bytes));
    }

    /**
     * Read a {@link PGPKeyRing} (either {@link PGPSecretKeyRing} or {@link PGPPublicKeyRing}) from the given
     * ASCII armored string.
     *
     * @param asciiArmored ASCII armored OpenPGP key or certificate
     * @return key ring
     * @throws IOException in case of an IO error
     */
    @Nullable
    public PGPKeyRing keyRing(@Nonnull String asciiArmored)
            throws IOException {
        return keyRing(asciiArmored.getBytes(UTF8));
    }

    @Nullable
    public PGPPublicKeyRing publicKeyRing(@Nonnull InputStream inputStream)
            throws IOException {
        return readPublicKeyRing(inputStream);
    }

    @Nullable
    public PGPPublicKeyRing publicKeyRing(@Nonnull byte[] bytes)
            throws IOException {
        return publicKeyRing(new ByteArrayInputStream(bytes));
    }

    @Nullable
    public PGPPublicKeyRing publicKeyRing(@Nonnull String asciiArmored)
            throws IOException {
        return publicKeyRing(asciiArmored.getBytes(UTF8));
    }

    @Nonnull
    public PGPPublicKeyRingCollection publicKeyRingCollection(@Nonnull InputStream inputStream)
            throws IOException {
        return readPublicKeyRingCollection(inputStream);
    }

    @Nonnull
    public PGPPublicKeyRingCollection publicKeyRingCollection(@Nonnull byte[] bytes)
            throws IOException {
        return publicKeyRingCollection(new ByteArrayInputStream(bytes));
    }

    @Nonnull
    public PGPPublicKeyRingCollection publicKeyRingCollection(@Nonnull String asciiArmored)
            throws IOException {
        return publicKeyRingCollection(asciiArmored.getBytes(UTF8));
    }

    @Nullable
    public PGPSecretKeyRing secretKeyRing(@Nonnull InputStream inputStream)
            throws IOException {
        return readSecretKeyRing(inputStream);
    }

    @Nullable
    public PGPSecretKeyRing secretKeyRing(@Nonnull byte[] bytes)
            throws IOException {
        return secretKeyRing(new ByteArrayInputStream(bytes));
    }

    @Nullable
    public PGPSecretKeyRing secretKeyRing(@Nonnull String asciiArmored)
            throws IOException {
        return secretKeyRing(asciiArmored.getBytes(UTF8));
    }

    @Nonnull
    public PGPSecretKeyRingCollection secretKeyRingCollection(@Nonnull InputStream inputStream)
            throws IOException {
        return readSecretKeyRingCollection(inputStream);
    }

    @Nonnull
    public PGPSecretKeyRingCollection secretKeyRingCollection(@Nonnull byte[] bytes)
            throws IOException {
        return secretKeyRingCollection(new ByteArrayInputStream(bytes));
    }

    @Nonnull
    public PGPSecretKeyRingCollection secretKeyRingCollection(@Nonnull String asciiArmored)
            throws IOException {
        return secretKeyRingCollection(asciiArmored.getBytes(UTF8));
    }

    @Nonnull
    public PGPKeyRingCollection keyRingCollection(@Nonnull InputStream inputStream, boolean isSilent)
            throws IOException, PGPException {
        return readKeyRingCollection(inputStream, isSilent);
    }

    @Nonnull
    public PGPKeyRingCollection keyRingCollection(@Nonnull byte[] bytes, boolean isSilent)
            throws IOException, PGPException {
        return keyRingCollection(new ByteArrayInputStream(bytes), isSilent);
    }

    @Nonnull
    public PGPKeyRingCollection keyRingCollection(@Nonnull String asciiArmored, boolean isSilent)
            throws IOException, PGPException {
        return keyRingCollection(asciiArmored.getBytes(UTF8), isSilent);
    }

    /**
     * Read a {@link PGPKeyRing} (either {@link PGPSecretKeyRing} or {@link PGPPublicKeyRing}) from the given
     * {@link InputStream}.
     * This method will attempt to read at most {@link #MAX_ITERATIONS} objects from the stream before aborting.
     * The first {@link PGPPublicKeyRing} or {@link PGPSecretKeyRing} will be returned.
     *
     * @param inputStream inputStream containing the OpenPGP key or certificate
     * @return key ring
     * @throws IOException in case of an IO error
     */
    @Nullable
    public static PGPKeyRing readKeyRing(@Nonnull InputStream inputStream)
            throws IOException {
        return readKeyRing(inputStream, MAX_ITERATIONS);
    }

    /**
     * Read a {@link PGPKeyRing} (either {@link PGPSecretKeyRing} or {@link PGPPublicKeyRing}) from the given
     * {@link InputStream}.
     * This method will attempt to read at most <pre>maxIterations</pre> objects from the stream before aborting.
     * The first {@link PGPPublicKeyRing} or {@link PGPSecretKeyRing} will be returned.
     *
     * @param inputStream inputStream containing the OpenPGP key or certificate
     * @param maxIterations maximum number of objects that are read before the method will abort
     * @return key ring
     * @throws IOException in case of an IO error
     */
    @Nullable
    public static PGPKeyRing readKeyRing(@Nonnull InputStream inputStream, int maxIterations)
            throws IOException {
        PGPObjectFactory objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(
                ArmorUtils.getDecoderStream(inputStream));
        int i = 0;
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
                return (PGPSecretKeyRing) next;
            }
            if (next instanceof PGPPublicKeyRing) {
                return (PGPPublicKeyRing) next;
            }
        } while (++i < maxIterations);

        throw new IOException("Loop exceeded max iteration count.");
    }

    @Nullable
    public static PGPPublicKeyRing readPublicKeyRing(@Nonnull InputStream inputStream)
            throws IOException {
        return readPublicKeyRing(inputStream, MAX_ITERATIONS);
    }

    /**
     * Read a public key ring from the provided {@link InputStream}.
     * If more than maxIterations PGP packets are encountered before a {@link PGPPublicKeyRing} is read,
     * an {@link IOException} is thrown.
     *
     * @param inputStream input stream
     * @param maxIterations max iterations before abort
     * @return public key ring
     *
     * @throws IOException in case of an IO error or exceeding of max iterations
     */
    @Nullable
    public static PGPPublicKeyRing readPublicKeyRing(@Nonnull InputStream inputStream, int maxIterations)
            throws IOException {
        PGPObjectFactory objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(
                ArmorUtils.getDecoderStream(inputStream));
        int i = 0;
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
        } while (++i < maxIterations);

        throw new IOException("Loop exceeded max iteration count.");
    }

    @Nonnull
    public static PGPPublicKeyRingCollection readPublicKeyRingCollection(@Nonnull InputStream inputStream)
            throws IOException {
        return readPublicKeyRingCollection(inputStream, MAX_ITERATIONS);
    }

    /**
     * Read a public key ring collection from the provided {@link InputStream}.
     * If more than maxIterations PGP packets are encountered before the stream is exhausted,
     * an {@link IOException} is thrown.
     * If the stream contain secret key packets, their public key parts are extracted and returned.
     *
     * @param inputStream input stream
     * @param maxIterations max iterations before abort
     * @return public key ring collection
     *
     * @throws IOException in case of an IO error or exceeding of max iterations
     */
    @Nonnull
    public static PGPPublicKeyRingCollection readPublicKeyRingCollection(@Nonnull InputStream inputStream, int maxIterations)
            throws IOException {
        PGPObjectFactory objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(
                ArmorUtils.getDecoderStream(inputStream));

        List<PGPPublicKeyRing> rings = new ArrayList<>();
        int i = 0;
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
                continue;
            }
            // Parse public keys from secret keys
            if (next instanceof PGPSecretKeyRing) {
                rings.add(PGPainless.extractCertificate((PGPSecretKeyRing) next));
                continue;
            }
            if (next instanceof PGPPublicKeyRingCollection) {
                PGPPublicKeyRingCollection collection = (PGPPublicKeyRingCollection) next;
                Iterator<PGPPublicKeyRing> iterator = collection.getKeyRings();
                while (iterator.hasNext()) {
                    rings.add(iterator.next());
                }
            }
        } while (++i < maxIterations);

        throw new IOException("Loop exceeded max iteration count.");
    }

    @Nullable
    public static PGPSecretKeyRing readSecretKeyRing(@Nonnull InputStream inputStream)
            throws IOException {
        return readSecretKeyRing(inputStream, MAX_ITERATIONS);
    }

    /**
     * Read a secret key ring from the provided {@link InputStream}.
     * If more than maxIterations PGP packets are encountered before a {@link PGPSecretKeyRing} is read,
     * an {@link IOException} is thrown.
     *
     * @param inputStream input stream
     * @param maxIterations max iterations before abort
     * @return public key ring
     *
     * @throws IOException in case of an IO error or exceeding of max iterations
     */
    @Nullable
    public static PGPSecretKeyRing readSecretKeyRing(@Nonnull InputStream inputStream, int maxIterations)
            throws IOException {
        InputStream decoderStream = ArmorUtils.getDecoderStream(inputStream);
        PGPObjectFactory objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(decoderStream);
        int i = 0;
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
        } while (++i < maxIterations);

        throw new IOException("Loop exceeded max iteration count.");
    }

    @Nonnull
    public static PGPSecretKeyRingCollection readSecretKeyRingCollection(@Nonnull InputStream inputStream)
            throws IOException {
        return readSecretKeyRingCollection(inputStream, MAX_ITERATIONS);
    }

    /**
     * Read a secret key ring collection from the provided {@link InputStream}.
     * If more than maxIterations PGP packets are encountered before the stream is exhausted,
     * an {@link IOException} is thrown.
     *
     * @param inputStream input stream
     * @param maxIterations max iterations before abort
     * @return secret key ring collection
     *
     * @throws IOException in case of an IO error or exceeding of max iterations
     */
    @Nonnull
    public static PGPSecretKeyRingCollection readSecretKeyRingCollection(@Nonnull InputStream inputStream,
                                                                         int maxIterations)
            throws IOException {
        PGPObjectFactory objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(
                ArmorUtils.getDecoderStream(inputStream));

        List<PGPSecretKeyRing> rings = new ArrayList<>();
        int i = 0;
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
        } while (++i < maxIterations);

        throw new IOException("Loop exceeded max iteration count.");
    }

    @Nonnull
    public static PGPKeyRingCollection readKeyRingCollection(@Nonnull InputStream inputStream, boolean isSilent)
            throws IOException, PGPException {
        return new PGPKeyRingCollection(inputStream, isSilent);
    }
}
