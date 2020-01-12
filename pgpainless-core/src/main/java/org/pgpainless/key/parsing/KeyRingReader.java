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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.pgpainless.key.collection.PGPKeyRing;

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

    public PGPKeyRing keyRing(@Nullable InputStream publicIn, @Nullable InputStream secretIn) throws IOException, PGPException {
        return readKeyRing(publicIn, secretIn);
    }

    public PGPKeyRing keyRing(@Nullable byte[] publicBytes, @Nullable byte[] secretBytes) throws IOException, PGPException {
        return keyRing(
                publicBytes != null ? new ByteArrayInputStream(publicBytes) : null,
                secretBytes != null ? new ByteArrayInputStream(secretBytes) : null
        );
    }

    public PGPKeyRing keyRing(@Nullable String asciiPublic, @Nullable String asciiSecret) throws IOException, PGPException {
        return keyRing(
                asciiPublic != null ? asciiPublic.getBytes(UTF8) : null,
                asciiSecret != null ? asciiSecret.getBytes(UTF8) : null
        );
    }

    /*
    STATIC METHODS
     */

    public static PGPPublicKeyRing readPublicKeyRing(@Nonnull InputStream inputStream) throws IOException {
        return new PGPPublicKeyRing(
                PGPUtil.getDecoderStream(inputStream),
                new BcKeyFingerprintCalculator());
    }

    public static PGPPublicKeyRingCollection readPublicKeyRingCollection(@Nonnull InputStream inputStream)
            throws IOException, PGPException {
        return new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(inputStream),
                new BcKeyFingerprintCalculator());
    }

    public static PGPSecretKeyRing readSecretKeyRing(@Nonnull InputStream inputStream) throws IOException, PGPException {
        return new PGPSecretKeyRing(
                PGPUtil.getDecoderStream(inputStream),
                new BcKeyFingerprintCalculator());
    }

    public static PGPSecretKeyRingCollection readSecretKeyRingCollection(@Nonnull InputStream inputStream)
            throws IOException, PGPException {
        return new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(inputStream),
                new BcKeyFingerprintCalculator());
    }

    public static PGPKeyRing readKeyRing(@Nullable InputStream publicIn, @Nullable InputStream secretIn) throws IOException, PGPException {
        validateStreamsNotBothNull(publicIn, secretIn);

        PGPPublicKeyRing publicKeys = maybeReadPublicKeys(publicIn);
        PGPSecretKeyRing secretKeys = maybeReadSecretKeys(secretIn);

        return asPGPKeyRing(publicKeys, secretKeys);
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

    private static PGPKeyRing asPGPKeyRing(PGPPublicKeyRing publicKeys, PGPSecretKeyRing secretKeys) {
        if (secretKeys == null) {
            return new PGPKeyRing(publicKeys);
        }
        if (publicKeys == null) {
            return new PGPKeyRing(secretKeys);
        }
        return new PGPKeyRing(publicKeys, secretKeys);
    }
}
