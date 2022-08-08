// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.parsing;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.MarkerPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.opentest4j.TestAbortedException;
import org.pgpainless.PGPainless;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.collection.PGPKeyRingCollection;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.signature.SignatureUtils;
import org.pgpainless.util.ArmoredOutputStreamFactory;
import org.pgpainless.util.TestUtils;

class KeyRingReaderTest {

    private InputStream requireResource(String resourceName) {
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream(resourceName);
        if (inputStream == null) {
            throw new TestAbortedException("Cannot read resource " + resourceName + ": InputStream is null.");
        }
        return inputStream;
    }

    private byte[] readFromResource(String resourceName) throws IOException {
        InputStream inputStream = requireResource(resourceName);
        return Streams.readAll(inputStream);
    }

    @Test
    public void assertThatPGPUtilsDetectAsciiArmoredData() throws IOException, PGPException {
        InputStream inputStream = requireResource("pub_keys_10_pieces.asc");

        InputStream possiblyArmored = PGPUtil.getDecoderStream(PGPUtil.getDecoderStream(inputStream));

        PGPPublicKeyRingCollection collection = new PGPPublicKeyRingCollection(
                possiblyArmored, ImplementationFactory.getInstance().getKeyFingerprintCalculator());
        assertEquals(10, collection.size());
    }

    @Test
    void publicKeyRingCollectionFromStream() throws IOException, PGPException {
        InputStream inputStream = requireResource("pub_keys_10_pieces.asc");
        PGPPublicKeyRingCollection rings = PGPainless.readKeyRing().publicKeyRingCollection(inputStream);
        assertEquals(10, rings.size());
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
        assertEquals(10, parsedRings.size());
    }

    @Test
    void publicKeyRingCollectionFromString() throws IOException, PGPException {
        String armoredString = new String(readFromResource("pub_keys_10_pieces.asc"));
        InputStream inputStream = new ByteArrayInputStream(armoredString.getBytes(StandardCharsets.UTF_8));
        PGPPublicKeyRingCollection rings = PGPainless.readKeyRing().publicKeyRingCollection(inputStream);
        assertEquals(10, rings.size());
    }

    @Test
    void publicKeyRingCollectionFromBytes() throws IOException, PGPException {
        byte[] bytes = readFromResource("pub_keys_10_pieces.asc");
        InputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        PGPPublicKeyRingCollection rings = PGPainless.readKeyRing().publicKeyRingCollection(byteArrayInputStream);
        assertEquals(10, rings.size());
    }

    /**
     * One armored pub key
     */
    @Test
    void parsePublicKeysSingleArmored() throws IOException, PGPException {
        assertEquals(1, getPgpPublicKeyRingsFromResource("single_pub_key_armored.asc").size());
    }

    /**
     * One binary pub key
     */
    @Test
    void parsePublicKeysSingleBinary() throws IOException, PGPException {
        assertEquals(1, getPgpPublicKeyRingsFromResource("single_pub_key_binary.key").size());
    }

    /**
     * Many armored pub keys with a single -----BEGIN PGP PUBLIC KEY BLOCK-----...-----END PGP PUBLIC KEY BLOCK-----
     */
    @Test
    void parsePublicKeysMultiplyArmoredSingleHeader() throws IOException, PGPException {
        assertEquals(10, getPgpPublicKeyRingsFromResource("10_pub_keys_armored_single_header.asc").size());
    }

    /**
     * Many armored pub keys where each has own -----BEGIN PGP PUBLIC KEY BLOCK-----...-----END PGP PUBLIC KEY BLOCK-----
     */
    @Test
    void parsePublicKeysMultiplyArmoredOwnHeader() throws IOException, PGPException {
        assertEquals(10, getPgpPublicKeyRingsFromResource("10_pub_keys_armored_own_header.asc").size());
    }

    /**
     * Many armored pub keys where each has own -----BEGIN PGP PUBLIC KEY BLOCK-----...-----END PGP PUBLIC KEY BLOCK-----.
     * Each of those blocks can have a different count of keys.
     */
    @Test
    void parsePublicKeysMultiplyArmoredOwnWithSingleHeader() throws IOException, PGPException {
        assertEquals(10, getPgpPublicKeyRingsFromResource("10_pub_keys_armored_own_with_single_header.asc").size());
    }

    /**
     * Many binary pub keys
     */
    @Test
    void parsePublicKeysMultiplyBinary() throws IOException, PGPException {
        assertEquals(10, getPgpPublicKeyRingsFromResource("10_pub_keys_binary.key").size());
    }

    /**
     * One armored private key
     */
    @Test
    void parseSecretKeysSingleArmored() throws IOException, PGPException {
        assertEquals(1, getPgpSecretKeyRingsFromResource("single_prv_key_armored.asc").size());
    }

    /**
     * One binary private key
     */
    @Test
    void parseSecretKeysSingleBinary() throws IOException, PGPException {
        assertEquals(1, getPgpSecretKeyRingsFromResource("single_prv_key_binary.key").size());
    }

    /**
     * Many armored private keys with a single
     * -----BEGIN PGP PRIVATE KEY BLOCK-----...-----END PGP PRIVATE KEY BLOCK-----
     */
    @Test
    void parseSecretKeysMultiplyArmoredSingleHeader() throws IOException, PGPException {
        assertEquals(10, getPgpSecretKeyRingsFromResource("10_prv_keys_armored_single_header.asc").size());
    }

    /**
     * Many armored private keys where each has own -----BEGIN PGP PRIVATE KEY BLOCK-----...-----END PGP PRIVATE KEY BLOCK-----
     */
    @Test
    void parseSecretKeysMultiplyArmoredOwnHeader() throws IOException, PGPException {
        assertEquals(10, getPgpSecretKeyRingsFromResource("10_prv_keys_armored_own_header.asc").size());
    }

    /**
     * Many armored private keys where each has own -----BEGIN PGP PRIVATE KEY BLOCK-----...-----END PGP PRIVATE KEY BLOCK-----.
     * Each of those blocks can have a different count of keys.
     */
    @Test
    void parseSecretKeysMultiplyArmoredOwnWithSingleHeader() throws IOException, PGPException {
        assertEquals(10, getPgpSecretKeyRingsFromResource("10_prv_keys_armored_own_with_single_header.asc").size());
    }

    /**
     * Many binary private keys
     */
    @Test
    void parseSecretKeysMultiplyBinary() throws IOException, PGPException {
        assertEquals(10, getPgpSecretKeyRingsFromResource("10_prv_keys_binary.key").size());
    }

    /**
     * Many armored keys(private or pub) where each has own -----BEGIN PGP ... KEY BLOCK-----...-----END PGP ... KEY BLOCK-----
     */
    @Test
    void parseKeysMultiplyArmoredOwnHeader() throws IOException, PGPException {
        assertEquals(10, getPGPKeyRingsFromResource("10_prv_and_pub_keys_armored_own_header.asc").size());
    }

    /**
     * Many armored keys(private or pub) where each has own -----BEGIN PGP ... KEY BLOCK-----...-----END PGP ... KEY BLOCK-----
     * Each of those blocks can have a different count of keys.
     */
    @Test
    void parseKeysMultiplyArmoredOwnWithSingleHeader() throws IOException, PGPException {
        assertEquals(10, getPGPKeyRingsFromResource("10_prv_and_pub_keys_armored_own_with_single_header.asc").size());
    }

    /**
     * Many binary keys(private or pub)
     */
    @Test
    void parseKeysMultiplyBinary() throws IOException, PGPException {
        assertEquals(10, getPGPKeyRingsFromResource("10_prv_and_pub_keys_binary.key").size());
    }

    private PGPKeyRingCollection getPGPKeyRingsFromResource(String fileName)
            throws IOException, PGPException {
        return PGPainless.readKeyRing().keyRingCollection(requireResource(fileName), true);
    }

    private PGPPublicKeyRingCollection getPgpPublicKeyRingsFromResource(String fileName)
            throws IOException, PGPException {
        return PGPainless.readKeyRing().publicKeyRingCollection(requireResource(fileName));
    }

    private PGPSecretKeyRingCollection getPgpSecretKeyRingsFromResource(String fileName)
            throws IOException, PGPException {
        return PGPainless.readKeyRing().secretKeyRingCollection(requireResource(fileName));
    }

    @Test
    public void testReadSecretKeyIgnoresMarkerPacket() throws IOException {
        String markerAndKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Version: PGPainless\n" +
                "Comment: Secret Key with prepended Marker Packet\n" +
                "\n" +
                "qANQR1CUWARg6WWBFgkrBgEEAdpHDwEBB0AyPTMeZL9XZtTedc9j8uX6igs+ZPGX\n" +
                "KfJGSem/zCxrogABAMAXMTtEsEXDd90tgD2oasEQ9NNDKsHIxStLbhbu/W0GDzu0\n" +
                "FGFsaWNlQHBncGFpbmxlc3Mub3JniHgEExYKACAFAmDpZYECGwEFFgIDAQAECwkI\n" +
                "BwUVCgkICwIeAQIZAQAKCRBzXl6xxUHAzuckAP9j7FYdXB4y1G+qC8PxRWygnDLC\n" +
                "3bgoJr+8mSBw8oGGowD/akhhuiU/EIFIG0A+kATN92AlJYLbq73sKF+1pIpPcA6c\n" +
                "XQRg6WWBEgorBgEEAZdVAQUBAQdA1RexkLKsWJtxG82lsiaBpiUzjayFFlEpHhZv\n" +
                "NemY+gQDAQgHAAD/ZluthWe9mBdbJxkq3+XGK3EBvFCSkTqEjAOeZpYRgOAPOIh1\n" +
                "BBgWCgAdBQJg6WWBAhsMBRYCAwEABAsJCAcFFQoJCAsCHgEACgkQc15escVBwM4U\n" +
                "HwEAjTd22074lQ4EsL/g6P6wVSrdIfxF6Sgx5652uKD2Cx0A/iR+3R1XlQd9+64G\n" +
                "BDgLpvi4qox59RoXyLDZ1TDtnGQFnFgEYOllgRYJKwYBBAHaRw8BAQdA7+NE2Y83\n" +
                "woDWXUIPQANQcskNOcwUU9hDw+qXxhCysesAAQDSgvEGDhoXcs8bJFrsTDrxugyl\n" +
                "e1QRBde52d4PZfxOHw48iNUEGBYKAH0FAmDpZYECGwIFFgIDAQAECwkIBwUVCgkI\n" +
                "CwIeAV8gBBkWCgAGBQJg6WWBAAoJEAZefiHacdJCCKYA/j+8mNlLNfeoBKx3vDxq\n" +
                "PWB3C0n/RZdeV4pz3EsT46MyAP9fCBzLADQeSwNv4BCWl5EGv6YMlg0+S1Q0A3Cn\n" +
                "lrtBCwAKCRBzXl6xxUHAzn9hAQCdTCa8P3aE8jbUav/eCSLsr5+ELi4ODg5ZAZaN\n" +
                "GlNPVAD/byyQfgQgtxrdf7sHBEg2+CCEtac6vvTyq6o9ndW3owg=\n" +
                "=9jtR\n" +
                "-----END PGP PRIVATE KEY BLOCK-----";

        PGPSecretKeyRing secretKey = PGPainless.readKeyRing().secretKeyRing(markerAndKey);
        assertEquals(
                new OpenPgpV4Fingerprint("562584F8730F39FCB02AACAE735E5EB1C541C0CE"),
                new OpenPgpV4Fingerprint(secretKey));
    }

    @Test
    public void testReadCertificateIgnoresMarkerPacket() throws IOException {
        String markerAndCert = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "Version: PGPainless\n" +
                "Comment: Certificate with prepended Marker Packet\n" +
                "\n" +
                "qANQR1CYMwRg6WcmFgkrBgEEAdpHDwEBB0D33FQiRhS7lvYXVxYqHK5iFiXE9dO0\n" +
                "rdNZ8i/YCVquLbQUYWxpY2VAcGdwYWlubGVzcy5vcmeIeAQTFgoAIAUCYOlnJgIb\n" +
                "AQUWAgMBAAQLCQgHBRUKCQgLAh4BAhkBAAoJEPbyu9T10peTttsBAKYt4qWIcf+U\n" +
                "J8rceVKr8WrbTbmYcMI948QKASqOmHQUAP0cBgIvJiTV6VPCzrr6y4DctgC2KmL2\n" +
                "WLUVB5oKTVpnB7g4BGDpZyYSCisGAQQBl1UBBQEBB0CbvjPN9vqxth2ICQ2C8TEf\n" +
                "VkSY44EghL9bs0aYfio1fgMBCAeIdQQYFgoAHQUCYOlnJgIbDAUWAgMBAAQLCQgH\n" +
                "BRUKCQgLAh4BAAoJEPbyu9T10peTJCQBAIkIfsgWjvc1lBHjoqK1TG0uO2bR3+2x\n" +
                "2fO2sB8s4ulAAQD/U5SWyx+2vw0Oi1GV6Do4xNKivJuNU5UgcbJj1SF+B7gzBGDp\n" +
                "ZyYWCSsGAQQB2kcPAQEHQJbuNdOUc35ZOo6+8cYuV+d+Gu+AZIhkA7zFsyLMrGsC\n" +
                "iNUEGBYKAH0FAmDpZyYCGwIFFgIDAQAECwkIBwUVCgkICwIeAV8gBBkWCgAGBQJg\n" +
                "6WcmAAoJEAqPm07pCscSwX8BAJkVbDWA6FBHVqmU9Iis+ZeQpolmeRdyuKm6AkYp\n" +
                "Z1jLAP9/MNtKOsbAvL1c7YXomytJAzgbx1hxWfFlD5rGSVuUBAAKCRD28rvU9dKX\n" +
                "kxnQAQCe6sgVoCIWw2nFwlEBnwEH4OIsRya79mBps6UZPv8g9QD+K8imuYR9zOwT\n" +
                "sFrPBVJ6f5HPPBEeQKMS0DBcg0NE3g4=\n" +
                "=6XFh\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";

        PGPPublicKeyRing certificate = PGPainless.readKeyRing().publicKeyRing(markerAndCert);

        assertEquals(
                new OpenPgpV4Fingerprint("4291C2BEF9B9209DF11128E7F6F2BBD4F5D29793"),
                new OpenPgpV4Fingerprint(certificate));
    }

    @Test
    public void testReadSecretKeyCollectionIgnoresMarkerPackets() throws PGPException, IOException {
        // Marker
        // Alice
        // Marker
        // Bob
        // Marker
        // Charlie
        // Marker
        String markersAndKeys = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Version: PGPainless\n" +
                "Comment: Secret Keys with injected Marker Packets\n" +
                "\n" +
                "qANQR1CUWARg6WhFFgkrBgEEAdpHDwEBB0DjH2IBKwAhdm84ZRVuR6q7JeXRteRQ\n" +
                "lf4QU7dbN3p3hQAA/iMLttV29lnH8K3FfcEcLVJ8ZjJJvDK0fbalvnf3zkXIEly0\n" +
                "FGFsaWNlQHBncGFpbmxlc3Mub3JniHgEExYKACAFAmDpaEUCGwEFFgIDAQAECwkI\n" +
                "BwUVCgkICwIeAQIZAQAKCRA6lTdYIKtst/3QAQDp4U2/4ntH3Fs5O1VHAK73WTO9\n" +
                "zNXiKuC063A0P/v2bgD8DSDk1eCoyLQcOh/9DfN4tMZJ/6FIwb3WCkxSw97Z0wic\n" +
                "XQRg6WhFEgorBgEEAZdVAQUBAQdAKxHYJTqkRCypuE7i4TsJbXXKN6Xmhbvmjhmd\n" +
                "u1drcUsDAQgHAAD/cThN8gH2r5bsPOUvrt55l1tT14Oj+Qjap9EUwiesQmASRIh1\n" +
                "BBgWCgAdBQJg6WhFAhsMBRYCAwEABAsJCAcFFQoJCAsCHgEACgkQOpU3WCCrbLew\n" +
                "0QD+MY2b9/zRjacoMisomi2x+CYeSoYgUQqKdJKJrEAok/QA/256NyiPO/cNQEdL\n" +
                "SzbUEZhme/DFg1rJN477Euo/hOMKnFcEYOloRRYJKwYBBAHaRw8BAQdAVKZYwF4Y\n" +
                "PUD1hq1E3Ilnxoa6KCGKsh2FJxkctYOKR1sAAPYoiQHf3NHuBsScEqYDXHjTdy8v\n" +
                "tYQzRmx+e9LDP4wHDz2I1QQYFgoAfQUCYOloRQIbAgUWAgMBAAQLCQgHBRUKCQgL\n" +
                "Ah4BXyAEGRYKAAYFAmDpaEUACgkQSVw6Evq5JjqvEAD8CR7NcQKUy1CDQ+M84p4m\n" +
                "nnbII6khqWoEq0bqazFPbKIBALwL6rhL5Ik/v8tW+JlRhDb4eBsWm5b4S1HaufxB\n" +
                "XJ0EAAoJEDqVN1ggq2y33+4BAMtcL9lP87M1dNcuNsrZ1m0+gmmG5J+/oSqtsZlW\n" +
                "SpxuAQDgI+IdPncg6nFCJMGwiL+qDb++c5o1pgflcGhVv2GlDqgDUEdQlFgEYOlo\n" +
                "RRYJKwYBBAHaRw8BAQdA5vhJLr3c1QjPwfX9FTJ+ziVG9J8l/Z6QHKJuSBiaAlEA\n" +
                "AQDm3Xt9X1YFRx//lSurYr7WRCBUHX3Ge1uOvlq9aomCNg84tBJib2JAcGdwYWlu\n" +
                "bGVzcy5vcmeIeAQTFgoAIAUCYOloRQIbAQUWAgMBAAQLCQgHBRUKCQgLAh4BAhkB\n" +
                "AAoJEMj0tCImK9SQ55cBAM8xAV/jDJN2lD18SbDPVZ+OJP/j9nrzZvQqb21Cds9C\n" +
                "AP0R94jcyEx3FyyRBvDyqqeGUjXsPgcAQlp17AboXm03DpxdBGDpaEUSCisGAQQB\n" +
                "l1UBBQEBB0B8eayqPueZm+rRCxnaxEXsUwhTL9UBaLtXJJK4Z1zEJAMBCAcAAP9N\n" +
                "9fbs6BVTorTT26wtXnvNCvXlIsR8XsAV5f8f5fgxsBQwiHUEGBYKAB0FAmDpaEUC\n" +
                "GwwFFgIDAQAECwkIBwUVCgkICwIeAQAKCRDI9LQiJivUkLbhAP9F7/xjyLvCRHtD\n" +
                "pX/GfI29Kfb111iCT52BKyq/TT5WvQEA48K2XSvutAVK91JMBg5A34HK+5PPZPUV\n" +
                "sG9Bb8RyRgucWARg6WhFFgkrBgEEAdpHDwEBB0CxEEGEc4hdT2qssJD0wWRY/ZsK\n" +
                "WEhK7rbQJ71HnM8TEQAA/j0LCQr+Mn8bBnASusPzI3ye8xHVBPEFX4GLIUwOH14H\n" +
                "DJWI1QQYFgoAfQUCYOloRQIbAgUWAgMBAAQLCQgHBRUKCQgLAh4BXyAEGRYKAAYF\n" +
                "AmDpaEUACgkQRVTyVd6iXcyLagD/RHqcDj4n9M3wZABra+R2xESqnFjeivlirPDE\n" +
                "4aRAsyIBAO5CN/BgUbAaPsjMgv9LK6lQKgdMCqWDpOyLxdeD33cFAAoJEMj0tCIm\n" +
                "K9SQb7kA/16WbqBaoKCT86JR0fyRHnqv0OpkiLq/V0HshelcRhe2AQCM6QOO7fIr\n" +
                "uPy0wh0YKJnERx4zZRbmsbh6sWjNaUiIBagDUEdQlFgEYOloRRYJKwYBBAHaRw8B\n" +
                "AQdA9patkgJRlLYFoUHLXLADFhQ1BaQvX4MVbIZSiSO7BMQAAQCp6Cw8TyThR78B\n" +
                "mCgF2Z4sN3Z0giB7Vt586eeJhJyejA9OtBZjaGFybGllQHBncGFpbmxlc3Mub3Jn\n" +
                "iHgEExYKACAFAmDpaEUCGwEFFgIDAQAECwkIBwUVCgkICwIeAQIZAQAKCRCdtvZK\n" +
                "TZDLyi7RAQDiFmvVuv9jCHbBfyjB7VpRVAW3FDRvuPdOXC9SWK4XBQD+PdLTljLw\n" +
                "YT3lOr6SXfELd3fmJYMDImoBguN3CBDyjQWcXQRg6WhFEgorBgEEAZdVAQUBAQdA\n" +
                "EBiuPXGJwy6w4QxWJPVo7aq7ZOWfZ46h6TZGwkK/FiYDAQgHAAD/WIN/9nM6taYW\n" +
                "JHJMxFbmyQivCkos9R2zwJi0/7uyVOARwIh1BBgWCgAdBQJg6WhFAhsMBRYCAwEA\n" +
                "BAsJCAcFFQoJCAsCHgEACgkQnbb2Sk2Qy8oKqgEAgVs1Zn7D8h7PFufOjbry2mbC\n" +
                "xIY720qMUBjMJ3k6Up8BANs8So9Bza+PSSzkSl02FMO35mdSaTM0wN6FjC+p52cA\n" +
                "nFgEYOloRRYJKwYBBAHaRw8BAQdAS0Hu07LjoCfmiRIRW+VuxI1lR6l5eeJ90yCd\n" +
                "UEi00tkAAQDKneHa3lRE7pE16gK/h+EHeQ9aVs2qIp6XtM0Izu1ANBEliNUEGBYK\n" +
                "AH0FAmDpaEUCGwIFFgIDAQAECwkIBwUVCgkICwIeAV8gBBkWCgAGBQJg6WhFAAoJ\n" +
                "EBp7XFqQf6Zlh+sA/RDpmtiDmN03eF3e3LJiZsUd/sZDOU9D/Phkk6L8LjdRAQD/\n" +
                "UMghkY6FoQgblW4jVUJ3JaLFJeTgZXJE2s8TxJj6CAAKCRCdtvZKTZDLypYsAP0R\n" +
                "HqkNloRGvPXmbC44XsMe7oMu0DcJqu2En7UzxeLNmQEAhmYXXZXcGezCASlbwX7B\n" +
                "ErE+7aqGe7NeySfX+Dq2JQ2oA1BHUA==\n" +
                "=Jgh3\n" +
                "-----END PGP PRIVATE KEY BLOCK-----";

        PGPSecretKeyRingCollection secretKeys = PGPainless.readKeyRing().secretKeyRingCollection(markersAndKeys);
        assertEquals(3, secretKeys.size());
    }

    @Test
    public void testReadCertificateCollectionIgnoresMarkerPackets() throws PGPException, IOException {
        String markersAndCerts = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "Version: PGPainless\n" +
                "Comment: Certificates with injected Marker Packets\n" +
                "\n" +
                "qANQR1CYMwRg6WlFFgkrBgEEAdpHDwEBB0D8DA8Ljt557GZn8wDFJPzeBv2A70fC\n" +
                "h92MkTs17VoYILQUYWxpY2VAcGdwYWlubGVzcy5vcmeIeAQTFgoAIAUCYOlpRQIb\n" +
                "AQUWAgMBAAQLCQgHBRUKCQgLAh4BAhkBAAoJEJB0aoL4SmmAukUA/igDja1VmFWc\n" +
                "CIO5Usj+XT+mpWw/wBS2sJoUwVOBgNodAP9flvbOQsnYCtFcK8Zaixn2Y5MCGktg\n" +
                "zPR4ViHqo3QrALg4BGDpaUUSCisGAQQBl1UBBQEBB0D2uMrObpVE1tLfcfC9Ol3k\n" +
                "351KW9wfrVmgI76ckUuBdgMBCAeIdQQYFgoAHQUCYOlpRQIbDAUWAgMBAAQLCQgH\n" +
                "BRUKCQgLAh4BAAoJEJB0aoL4SmmAW8sBAP42LkP5S/CwUhpiyfmMfydwG25g6nWv\n" +
                "s413zKKIrDBNAP9UQShowbpRIhQkO3/fsmI+1kwujLXWEgV4ltuktmYKBrgzBGDp\n" +
                "aUUWCSsGAQQB2kcPAQEHQOfCezOL4q6QbC4+6LmedQ8Ok4O1j+AS7FMTF/4jaEYr\n" +
                "iNUEGBYKAH0FAmDpaUUCGwIFFgIDAQAECwkIBwUVCgkICwIeAV8gBBkWCgAGBQJg\n" +
                "6WlFAAoJEJMPNY2nAmZ8aecA/3+Vx3jOX3ky+kxjIJgdpZV4zCK4+xxn7jc/K4gr\n" +
                "BiKpAP9PZ9WPizfbbE3JX7ubLmDjLXAT0aDmiPESZB+tiiyADAAKCRCQdGqC+Epp\n" +
                "gBx9AQD7zbQlhjs4W6HXoStlotRUjCSBuJA4Gb0EkQUyG8sTeAEA5EAb4JgFiloR\n" +
                "Q2KOJvrzO0ESO+dKKDv+BtPXl49m0AyoA1BHUJgzBGDpaUUWCSsGAQQB2kcPAQEH\n" +
                "QLhQd9y5pedCXnzvA0GJJgdp36JCmxrzI3Nxj0rZRLmHtBJib2JAcGdwYWlubGVz\n" +
                "cy5vcmeIeAQTFgoAIAUCYOlpRQIbAQUWAgMBAAQLCQgHBRUKCQgLAh4BAhkBAAoJ\n" +
                "EDJI0AtDs041jU0A/0QlLxkjwi0cYVGg62/rAJ9Hi3O/g1w9TS1eExboCeQZAP9c\n" +
                "uQxnUgAAwnom8Mx7Rrydfb5nPS2a64AoNziw/zblD7g4BGDpaUUSCisGAQQBl1UB\n" +
                "BQEBB0D8s6a+rQ/JHzQILoOr0yHxG5b428c+rF39frfnlInQcAMBCAeIdQQYFgoA\n" +
                "HQUCYOlpRQIbDAUWAgMBAAQLCQgHBRUKCQgLAh4BAAoJEDJI0AtDs041yucBAKWG\n" +
                "vCrvcM7l0O4VUADPuBz0JfxKsLibeSiB9J8wzpAtAQCA2fKdDpDqcyrWtGDiIuko\n" +
                "Z6R6SdUquSCPPd/JuBCnCbgzBGDpaUUWCSsGAQQB2kcPAQEHQCtlUlAZuiXa1w6K\n" +
                "SMybCOy7RZ9ouH560bYNVFryciI5iNUEGBYKAH0FAmDpaUUCGwIFFgIDAQAECwkI\n" +
                "BwUVCgkICwIeAV8gBBkWCgAGBQJg6WlFAAoJEHasTR5i2pVLzhsBAMVbiy3J0OzK\n" +
                "4KCwel+M+Kq/IaVaQFjmyu/zgWLVr04zAQCZ6w5aMAK7GmpBIvks/vlt7qgkxhZy\n" +
                "E9V4pHGHcLD2BgAKCRAySNALQ7NONeQdAP9KBaYXbb/qcrqklTu7x1aYZNeAOnrZ\n" +
                "zl4GTIh5aHZ25wD9FrgSO2ebavHe5vZmME6HIxzC3lADS+18fjo5taeS6gOoA1BH\n" +
                "UJgzBGDpaUUWCSsGAQQB2kcPAQEHQAvooKeu5yJWMOH4QKXbNL+vtDtqckMNpM7o\n" +
                "CEJWp85htBZjaGFybGllQHBncGFpbmxlc3Mub3JniHgEExYKACAFAmDpaUUCGwEF\n" +
                "FgIDAQAECwkIBwUVCgkICwIeAQIZAQAKCRC4y4xSBWsKFSnzAQC5nGJaz0VAMbgt\n" +
                "Z2ellsVO/wjRssCr3gHIsrGnW6E0ZAD/UVarkzwzk/h1IXQK8TGbx7dLb2gCoJ+v\n" +
                "8smHe+3hawe4OARg6WlFEgorBgEEAZdVAQUBAQdAR4w1GbxLYm9V2kSq8ofRc6d8\n" +
                "fseZ1zig1fNIxcv3njcDAQgHiHUEGBYKAB0FAmDpaUUCGwwFFgIDAQAECwkIBwUV\n" +
                "CgkICwIeAQAKCRC4y4xSBWsKFXKAAQDyIqXxRmFozR6zP7/loI4YqfxDpwPFUevv\n" +
                "CisDkaTaaAEA6Pyi0Y0T3yoyR00RLgJnyDBbf/vtWVGp0IcFWZcLZQS4MwRg6WlF\n" +
                "FgkrBgEEAdpHDwEBB0DljpzDhVSzHgN2areAdxG1/1nZAkleDT/xyPUuXxbruYjV\n" +
                "BBgWCgB9BQJg6WlFAhsCBRYCAwEABAsJCAcFFQoJCAsCHgFfIAQZFgoABgUCYOlp\n" +
                "RQAKCRAYgL6ek003kO5bAP9vMBHKmn5GJIjrnvpwkog2TuLO/jcCnXwbes42EJ7t\n" +
                "BgEAhIuNp1QnQPlgDabVSLJlJyiBWP3A+xIh0UHuLRyr2QQACgkQuMuMUgVrChXV\n" +
                "1AD/dd5TWLYcbZJmLFW2gT0IslYVGZmZNO03WmKkahFoylIBANQ0Iu1y6j/vhGL6\n" +
                "r1zIt4pkvfxrlrxvxlk80IqcTsYMqANQR1A=\n" +
                "=aWCj\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";

        PGPPublicKeyRingCollection certificates = PGPainless.readKeyRing().publicKeyRingCollection(markersAndCerts);
        assertEquals(3, certificates.size());
    }

    @Test
    public void testReadSignatureIgnoresMarkerPacket() throws PGPException, IOException {
        String markerAndSignature = "-----BEGIN PGP SIGNATURE-----\n" +
                "Version: PGPainless\n" +
                "Comment: Signature with prepended Marker Packet\n" +
                "\n" +
                "qANQR1CIeAQTFgoAIAUCYOlqZgIbAQUWAgMBAAQLCQgHBRUKCQgLAh4BAhkBAAoJ\n" +
                "EAJI18O3wl3pF3AA/3PcUODYUYfaFtwOjhRnbSVJDpRf271yNGkbuRPI9q7vAQCo\n" +
                "nqxxfvd9VxfZCrdZc5gCbIxVUnbuBL2fjBqIoYQkDQ==\n" +
                "=S1jF\n" +
                "-----END PGP SIGNATURE-----";
        List<PGPSignature> signatureList = SignatureUtils.readSignatures(markerAndSignature);
        assertEquals(1, signatureList.size());
    }

    @Test
    public void testReadSecretKeysIgnoresMultipleMarkers() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing alice = PGPainless.generateKeyRing().modernKeyRing("alice@pgpainless.org");
        PGPSecretKeyRing bob = PGPainless.generateKeyRing().modernKeyRing("bob@pgpainless.org");
        MarkerPacket marker = TestUtils.getMarkerPacket();

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        ArmoredOutputStream armor = ArmoredOutputStreamFactory.get(bytes);
        armor.setHeader("Comment", "Secret Keys and an absurd amount of markers");
        BCPGOutputStream outputStream = new BCPGOutputStream(armor);

        for (int i = 0; i < 25; i++) {
            marker.encode(outputStream);
        }
        alice.encode(outputStream);
        for (int i = 0; i < 53; i++) {
            marker.encode(outputStream);
        }
        bob.encode(outputStream);
        for (int i = 0; i < 102; i++) {
            marker.encode(outputStream);
        }
        outputStream.close();
        armor.close();

        String armoredMess = bytes.toString();

        PGPSecretKeyRingCollection secretKeys = PGPainless.readKeyRing().secretKeyRingCollection(armoredMess);
        assertEquals(2, secretKeys.size());
        assertTrue(secretKeys.contains(alice.getSecretKey().getKeyID()));
        assertTrue(secretKeys.contains(bob.getSecretKey().getKeyID()));
    }

    @Test
    public void testReadingSecretKeysExceedsIterationLimit()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing alice = PGPainless.generateKeyRing().modernKeyRing("alice@pgpainless.org");
        MarkerPacket marker = TestUtils.getMarkerPacket();

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        ArmoredOutputStream armor = ArmoredOutputStreamFactory.get(bytes);
        BCPGOutputStream outputStream = new BCPGOutputStream(armor);

        for (int i = 0; i < 600; i++) {
            marker.encode(outputStream);
        }
        alice.encode(outputStream);

        assertThrows(IOException.class, () ->
                KeyRingReader.readSecretKeyRing(new ByteArrayInputStream(bytes.toByteArray()), 512));
    }

    @Test
    public void testReadingSecretKeyCollectionExceedsIterationLimit()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing alice = PGPainless.generateKeyRing().modernKeyRing("alice@pgpainless.org");
        PGPSecretKeyRing bob = PGPainless.generateKeyRing().modernKeyRing("bob@pgpainless.org");
        MarkerPacket marker = TestUtils.getMarkerPacket();

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        ArmoredOutputStream armor = ArmoredOutputStreamFactory.get(bytes);
        BCPGOutputStream outputStream = new BCPGOutputStream(armor);

        for (int i = 0; i < 600; i++) {
            marker.encode(outputStream);
        }
        alice.encode(outputStream);
        bob.encode(outputStream);

        assertThrows(IOException.class, () ->
                KeyRingReader.readSecretKeyRingCollection(new ByteArrayInputStream(bytes.toByteArray()), 512));
    }


    @Test
    public void testReadingPublicKeysExceedsIterationLimit()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing("alice@pgpainless.org");
        PGPPublicKeyRing alice = PGPainless.extractCertificate(secretKeys);
        MarkerPacket marker = TestUtils.getMarkerPacket();

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        ArmoredOutputStream armor = ArmoredOutputStreamFactory.get(bytes);
        BCPGOutputStream outputStream = new BCPGOutputStream(armor);

        for (int i = 0; i < 600; i++) {
            marker.encode(outputStream);
        }
        alice.encode(outputStream);

        assertThrows(IOException.class, () ->
                KeyRingReader.readPublicKeyRing(new ByteArrayInputStream(bytes.toByteArray()), 512));
    }

    @Test
    public void testReadingPublicKeyCollectionExceedsIterationLimit()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing sec1 = PGPainless.generateKeyRing().modernKeyRing("alice@pgpainless.org");
        PGPSecretKeyRing sec2 = PGPainless.generateKeyRing().modernKeyRing("bob@pgpainless.org");
        PGPPublicKeyRing alice = PGPainless.extractCertificate(sec1);
        PGPPublicKeyRing bob = PGPainless.extractCertificate(sec2);
        MarkerPacket marker = TestUtils.getMarkerPacket();

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        ArmoredOutputStream armor = ArmoredOutputStreamFactory.get(bytes);
        BCPGOutputStream outputStream = new BCPGOutputStream(armor);

        for (int i = 0; i < 600; i++) {
            marker.encode(outputStream);
        }
        alice.encode(outputStream);
        bob.encode(outputStream);

        assertThrows(IOException.class, () ->
                KeyRingReader.readPublicKeyRingCollection(new ByteArrayInputStream(bytes.toByteArray()), 512));
    }

    @Test
    public void testReadKeyRingWithBinaryPublicKey() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing("Alice <alice@pgpainless.org>");
        PGPPublicKeyRing publicKeys = PGPainless.extractCertificate(secretKeys);
        byte[] bytes = publicKeys.getEncoded();

        PGPKeyRing keyRing = PGPainless.readKeyRing()
                .keyRing(bytes);

        assertTrue(keyRing instanceof PGPPublicKeyRing);
        assertArrayEquals(keyRing.getEncoded(), publicKeys.getEncoded());
    }

    @Test
    public void testReadKeyRingWithBinarySecretKey() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing("Alice <alice@pgpainless.org>");
        byte[] bytes = secretKeys.getEncoded();

        PGPKeyRing keyRing = PGPainless.readKeyRing()
                .keyRing(bytes);

        assertTrue(keyRing instanceof PGPSecretKeyRing);
        assertArrayEquals(keyRing.getEncoded(), secretKeys.getEncoded());
    }

    @Test
    public void testReadKeyRingWithArmoredPublicKey() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing("Alice <alice@pgpainless.org>");
        PGPPublicKeyRing publicKeys = PGPainless.extractCertificate(secretKeys);
        String armored = PGPainless.asciiArmor(publicKeys);

        PGPKeyRing keyRing = PGPainless.readKeyRing()
                .keyRing(armored);

        assertTrue(keyRing instanceof PGPPublicKeyRing);
        assertArrayEquals(keyRing.getEncoded(), publicKeys.getEncoded());
    }

    @Test
    public void testReadKeyRingWithArmoredSecretKey() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing("Alice <alice@pgpainless.org>");
        String armored = PGPainless.asciiArmor(secretKeys);

        PGPKeyRing keyRing = PGPainless.readKeyRing()
                .keyRing(armored);

        assertTrue(keyRing instanceof PGPSecretKeyRing);
        assertArrayEquals(keyRing.getEncoded(), secretKeys.getEncoded());
    }
}
