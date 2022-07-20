// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.Test;
import org.pgpainless.key.util.KeyIdUtil;

public class MessageInspectorTest {

    @Test
    public void testBasicMessageInspection() throws PGPException, IOException {
        String message = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wV4DR2b2udXyHrYSAQdAO6LtuB8LenDp1EPVSSYn1QCmTSPjeXj9Qdel7t6Ozi8w\n" +
                "kewS+0AdZcvcd2PQEuCboilRAN4TTi9SziuSDNZe//suYHL7SRnOvX6mWSZoiKBm\n" +
                "0j8BlbKlRhBzcNDj6DSKfM/KBhRaw0U9fGs01gq+RNXIHOOnzVjLK18xTNEkx72F\n" +
                "Z1/i3TYsmy8B0mMKkNYtpMk=\n" +
                "=IICf\n" +
                "-----END PGP MESSAGE-----\n";

        MessageInspector.EncryptionInfo info = MessageInspector.determineEncryptionInfoForMessage(message);

        assertFalse(info.isPassphraseEncrypted());
        assertFalse(info.isSignedOnly());
        assertTrue(info.isEncrypted());
        assertEquals(1, info.getKeyIds().size());
        assertEquals(KeyIdUtil.fromLongKeyId("4766F6B9D5F21EB6"), (long) info.getKeyIds().get(0));
    }

    @Test
    public void testMultipleRecipientKeysAndPassphrase() throws PGPException, IOException {
        String message = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "jC4ECQMCtjbxGuer3wJgmQNX6L5nrJzkOEsnsFxyDYmqpqaFaMRHwARfX2huZdNd\n" +
                "hF4DTG6PmfbkcYQSAQdAxolEEp+NDhQXzf4/hN/4ihjSs16EoMVPxnQVZslvXm0w\n" +
                "pCmY/zAd1i3cJjNw2IXtCUpAIwjGc3pJzPxnkm0aBSS1ejxTqKy34MlostqEveB+\n" +
                "hF4DGDkHmmQLL6wSAQdAxdIJmu7Vbz12eG3lCUDuuwXW1s0ZsSftbUT3Ly+YMFIw\n" +
                "TadDYpy4pAAC82G8Z291zMiyctJE5dPAEWE5/sIguJSTeeM3ltocCMfx3ZCbKiov\n" +
                "jC4ECQMCssbl4ymUB6FgAVELIUXGolY6PgsnRmq3oBQbM7ysu+WsXm//CRXqfkgU\n" +
                "0kABN21rVlCCSrgAQq2vY4GWQ8OfiUzJOWH//63VDYMJ5ehou9eFtOXq2YW9IUy4\n" +
                "nxVuXey3iyihCFAfD8ZK1Rnh\n" +
                "=z6e0\n" +
                "-----END PGP MESSAGE-----";

        MessageInspector.EncryptionInfo info = MessageInspector.determineEncryptionInfoForMessage(message);

        assertTrue(info.isEncrypted());
        assertTrue(info.isPassphraseEncrypted());
        assertEquals(2, info.getKeyIds().size());
        assertFalse(info.isSignedOnly());
        assertTrue(info.getKeyIds().contains(KeyIdUtil.fromLongKeyId("4C6E8F99F6E47184")));
        assertTrue(info.getKeyIds().contains(KeyIdUtil.fromLongKeyId("1839079A640B2FAC")));
    }

    @Test
    public void testSignedOnlyMessage() throws PGPException, IOException {
        String message = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "owGbwMvMwCU2JftV+VJxWRbG0yJJDCDgkZqTk6+jEJ5flJOiyNVRysIgxsXAxsqU\n" +
                "GPbzCoMipwBMg5giy+9JdusX5zywTwq60QsTfj2J4a9ki6nKuVnu940q5qzl+aK3\n" +
                "89zdHzzyDBEdJg4asQcf3PBk+Cu1W/vQ1mMVW3fyTVc0VNe9PyktZlfcge2CbR8F\n" +
                "Dvxwv8UPAA==\n" +
                "=nt5n\n" +
                "-----END PGP MESSAGE-----";

        MessageInspector.EncryptionInfo info = MessageInspector.determineEncryptionInfoForMessage(message);

        assertTrue(info.isSignedOnly());

        assertFalse(info.isEncrypted());
        assertFalse(info.isPassphraseEncrypted());
        assertEquals(0, info.getKeyIds().size());
    }

    @Test
    public void testEncryptedAndSignedMessage() throws PGPException, IOException {
        String message = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "jC4ECQMCKFdrpiMTt8xgtZjkH60Nu4s+5THbPWOgyTmXkAeBAsmXDNWWuB5QSXFz\n" +
                "hF4DaM8R0fnHE6USAQdALJl6fCtB597Ub/GR3bxu3Uv2lirMA8bI2iGHUE7f0Rkw\n" +
                "ZNgmEk3YRGp+zddZoLp0WAIL0y4FLwUlMrR+YFYA37eAILiCwLEesIpvIoYq+fIu\n" +
                "0r4BJ/bM9oiCZGy7clpBQgOBFOTMR2fCO9ESVOaLwTGDJkVk6m+iLV1OYG6997vP\n" +
                "qHrg/zzy/U+xm90iHJzXoQ7yd2QZMU7llvC/otf5j14x3PCqd/rIxQrO2uc76Pef\n" +
                "Lh1JRHb7St4PC429HfE7pEAfFUej1I56U/ZCPwxa9f6je911jM4ZmZQTKJq3XZ3H\n" +
                "KK0Ymg5GrsBTEGFm4jb1p+V85PPhsIioX3np/N3fkIfxFguTGZza33/GHy61+DTy\n" +
                "=SZU6\n" +
                "-----END PGP MESSAGE-----";
        MessageInspector.EncryptionInfo info = MessageInspector.determineEncryptionInfoForMessage(message);

        // Message is encrypted, so we cannot determine if it is signed or not.
        // It is not signed only
        assertFalse(info.isSignedOnly());

        assertTrue(info.isEncrypted());
        assertTrue(info.isPassphraseEncrypted());
        assertEquals(1, info.getKeyIds().size());
    }

    @Test
    public void testPlaintextMessage() throws IOException, PGPException {
        String message = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "Comment: Literal Data\n" +
                "\n" +
                "yyl0CF9DT05TT0xFYXlXgUp1c3Qgc29tZSB1bmVuY3J5cHRlZCBkYXRhLg==\n" +
                "=jVNT\n" +
                "-----END PGP MESSAGE-----";

        MessageInspector.EncryptionInfo info = MessageInspector.determineEncryptionInfoForMessage(message);
        assertFalse(info.isEncrypted());
        assertFalse(info.isSignedOnly());
        assertFalse(info.isPassphraseEncrypted());
        assertTrue(info.getKeyIds().isEmpty());
    }

    @Test
    public void testCompressedPlaintextMessage() throws IOException, PGPException {
        String message = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: PGPainless\n" +
                "Comment: Compressed Literal Data\n" +
                "\n" +
                "owE7HVDCEe/s7xfs7+OaWBmxJDw1L08hIzOvJLVIwS0nMzU9NQ9Op0FoHRgDQ0Fe\n" +
                "YnKGHgA=\n" +
                "=jw3E\n" +
                "-----END PGP MESSAGE-----";

        MessageInspector.EncryptionInfo info = MessageInspector.determineEncryptionInfoForMessage(message);
        assertFalse(info.isEncrypted());
        assertFalse(info.isSignedOnly());
        assertFalse(info.isPassphraseEncrypted());
        assertTrue(info.getKeyIds().isEmpty());
    }
}
