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

    public PGPPublicKeyRing publicKeyRing(InputStream inputStream) throws IOException {
        return readPublicKeyRing(inputStream);
    }

    public PGPPublicKeyRing publicKeyRing(byte[] bytes) throws IOException {
        return publicKeyRing(new ByteArrayInputStream(bytes));
    }

    public PGPPublicKeyRing publicKeyRing(String asciiArmored) throws IOException {
        return publicKeyRing(asciiArmored.getBytes(UTF8));
    }

    public PGPPublicKeyRingCollection publicKeyRingCollection(InputStream inputStream)
            throws IOException, PGPException {
        return readPublicKeyRingCollection(inputStream);
    }

    public PGPPublicKeyRingCollection publicKeyRingCollection(byte[] bytes) throws IOException, PGPException {
        return publicKeyRingCollection(new ByteArrayInputStream(bytes));
    }

    public PGPPublicKeyRingCollection publicKeyRingCollection(String asciiArmored) throws IOException, PGPException {
        return publicKeyRingCollection(asciiArmored.getBytes(UTF8));
    }

    public PGPSecretKeyRing secretKeyRing(InputStream inputStream) throws IOException, PGPException {
        return readSecretKeyRing(inputStream);
    }

    public PGPSecretKeyRing secretKeyRing(byte[] bytes) throws IOException, PGPException {
        return secretKeyRing(new ByteArrayInputStream(bytes));
    }

    public PGPSecretKeyRing secretKeyRing(String asciiArmored) throws IOException, PGPException {
        return secretKeyRing(asciiArmored.getBytes(UTF8));
    }

    public PGPSecretKeyRingCollection secretKeyRingCollection(InputStream inputStream)
            throws IOException, PGPException {
        return readSecretKeyRingCollection(inputStream);
    }

    public PGPSecretKeyRingCollection secretKeyRingCollection(byte[] bytes) throws IOException, PGPException {
        return secretKeyRingCollection(new ByteArrayInputStream(bytes));
    }

    public PGPSecretKeyRingCollection secretKeyRingCollection(String asciiArmored) throws IOException, PGPException {
        return secretKeyRingCollection(asciiArmored.getBytes(UTF8));
    }

    public PGPKeyRing keyRing(InputStream publicIn, InputStream secretIn) throws IOException, PGPException {
        return readKeyRing(publicIn, secretIn);
    }

    public PGPKeyRing keyRing(byte[] publicBytes, byte[] secretBytes) throws IOException, PGPException {
        return keyRing(
                publicBytes != null ? new ByteArrayInputStream(publicBytes) : null,
                secretBytes != null ? new ByteArrayInputStream(secretBytes) : null
        );
    }

    public PGPKeyRing keyRing(String asciiPublic, String asciiSecret) throws IOException, PGPException {
        return keyRing(
                asciiPublic != null ? asciiPublic.getBytes(UTF8) : null,
                asciiSecret != null ? asciiSecret.getBytes(UTF8) : null
        );
    }

    /*
    STATIC METHODS
     */

    public static PGPPublicKeyRing readPublicKeyRing(InputStream inputStream) throws IOException {
        return new PGPPublicKeyRing(
                PGPUtil.getDecoderStream(inputStream),
                new BcKeyFingerprintCalculator());
    }

    public static PGPPublicKeyRingCollection readPublicKeyRingCollection(InputStream inputStream)
            throws IOException, PGPException {
        return new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(inputStream),
                new BcKeyFingerprintCalculator());
    }

    public static PGPSecretKeyRing readSecretKeyRing(InputStream inputStream) throws IOException, PGPException {
        return new PGPSecretKeyRing(
                PGPUtil.getDecoderStream(inputStream),
                new BcKeyFingerprintCalculator());
    }

    public static PGPSecretKeyRingCollection readSecretKeyRingCollection(InputStream inputStream)
            throws IOException, PGPException {
        return new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(inputStream),
                new BcKeyFingerprintCalculator());
    }

    public static PGPKeyRing readKeyRing(InputStream publicIn, InputStream secretIn) throws IOException, PGPException {
        PGPPublicKeyRing publicKeys = null;
        if (publicIn != null) {
            publicKeys = readPublicKeyRing(publicIn);
        }
        PGPSecretKeyRing secretKeys = null;
        if (secretIn != null) {
            secretKeys = readSecretKeyRing(secretIn);
        }
        return new PGPKeyRing(publicKeys, secretKeys);
    }
}
