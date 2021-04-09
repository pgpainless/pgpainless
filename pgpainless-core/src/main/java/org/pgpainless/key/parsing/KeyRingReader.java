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
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.collection.PGPKeyRingCollection;

public class KeyRingReader {

    public static final Charset UTF8 = Charset.forName("UTF-8");

    public @Nonnull PGPPublicKeyRing publicKeyRing(@Nonnull InputStream inputStream) throws IOException {
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

    public PGPSecretKeyRing secretKeyRing(@Nonnull InputStream inputStream) throws IOException, PGPException {
        return readSecretKeyRing(inputStream);
    }

    public PGPSecretKeyRing secretKeyRing(@Nonnull byte[] bytes) throws IOException, PGPException {
        return secretKeyRing(new ByteArrayInputStream(bytes));
    }

    public PGPSecretKeyRing secretKeyRing(@Nonnull String asciiArmored) throws IOException, PGPException {
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

    /*
    STATIC METHODS
     */

    public static PGPPublicKeyRing readPublicKeyRing(@Nonnull InputStream inputStream) throws IOException {
        return new PGPPublicKeyRing(
                PGPUtil.getDecoderStream(inputStream),
                ImplementationFactory.getInstance().getKeyFingerprintCalculator());
    }

    public static PGPPublicKeyRingCollection readPublicKeyRingCollection(@Nonnull InputStream inputStream)
            throws IOException, PGPException {
        return new PGPPublicKeyRingCollection(
                getDecoderStream(inputStream),
                ImplementationFactory.getInstance().getKeyFingerprintCalculator());
    }

    public static PGPSecretKeyRing readSecretKeyRing(@Nonnull InputStream inputStream) throws IOException, PGPException {
        return new PGPSecretKeyRing(
                PGPUtil.getDecoderStream(inputStream),
                ImplementationFactory.getInstance().getKeyFingerprintCalculator());
    }

    public static PGPSecretKeyRingCollection readSecretKeyRingCollection(@Nonnull InputStream inputStream)
            throws IOException, PGPException {
        return new PGPSecretKeyRingCollection(
                getDecoderStream(inputStream),
                ImplementationFactory.getInstance().getKeyFingerprintCalculator());
    }

    public static PGPKeyRingCollection readKeyRingCollection(@Nonnull InputStream inputStream, boolean isSilent)
            throws IOException, PGPException {
        return new PGPKeyRingCollection(
                getDecoderStream(inputStream),
                ImplementationFactory.getInstance().getKeyFingerprintCalculator(),
                isSilent);
    }

    private static void validateStreamsNotBothNull(InputStream publicIn, InputStream secretIn) {
        if (publicIn == null && secretIn == null) {
            throw new NullPointerException("publicIn and secretIn cannot be BOTH null.");
        }
    }

    private static PGPPublicKeyRing maybeReadPublicKeys(InputStream publicIn) throws IOException {
        if (publicIn != null) {
            return readPublicKeyRing(publicIn);
        }
        return null;
    }

    private static PGPSecretKeyRing maybeReadSecretKeys(InputStream secretIn) throws IOException, PGPException {
        if (secretIn != null) {
            return readSecretKeyRing(secretIn);
        }
        return null;
    }

    /**
     * Hacky workaround for #96.
     * For {@link PGPPublicKeyRingCollection#PGPPublicKeyRingCollection(InputStream, KeyFingerPrintCalculator)}
     * or {@link PGPSecretKeyRingCollection#PGPSecretKeyRingCollection(InputStream, KeyFingerPrintCalculator)}
     * to read all PGPKeyRings properly, we apparently have to make sure that the {@link InputStream} that is given
     * as constructor argument is a {@link PGPUtil.BufferedInputStreamExt}.
     * Since {@link PGPUtil#getDecoderStream(InputStream)} will return an {@link org.bouncycastle.bcpg.ArmoredInputStream}
     * if the underlying input stream contains armored data, we have to nest two method calls to make sure that the
     * end-result is a {@link PGPUtil.BufferedInputStreamExt}.
     *
     * This is a hacky solution.
     *
     * @param inputStream input stream
     * @return BufferedInputStreamExt
     */
    private static InputStream getDecoderStream(InputStream inputStream) throws IOException {
        return PGPUtil.getDecoderStream(PGPUtil.getDecoderStream(inputStream));
    }
}
