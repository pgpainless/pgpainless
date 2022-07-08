// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * V3 keys are not supported by PGPainless.
 * However, some basic functions like parsing the keys or converting a secret key to a certificate still work.
 */
public class V3KeyBehaviorTest {

    private static final String V3Cert = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "mQCNA2JqgDIAAAEEAOYdcIKFQ5ZWBx0D5DKwMMNFcIhFyqmfDJ0v23ehMxOkXN/o\n" +
            "HO/43+dq6ZqQn0gNw53Tp9no+EmcCYNrZuN0C4Zu8XHSyY6UB+CqzNkz/CwmV10E\n" +
            "dRDipcG1O6scJyy2MWpuOG67til+o+wOLgEkkVkSW8Bl2oqtzVVP4swtKLRZAAUR\n" +
            "tClKb2huIFEuIFNtaXRoIDwxMjM0NS42Nzg5QGNvbXB1c2VydmUuY29tPokAlQMF\n" +
            "EGJqgDJVT+LMLSi0WQEBgiwEALKQnuzza+oIgp7CAukW6qhUaOV/Cf3P4bWhru+v\n" +
            "8bED+YUOvgTytnXK1QUxQJ/PLnYV860NBRVR46kCtpZDgl+NeQe4O5lxbZVGHZy1\n" +
            "P+FUcbvUaA5ZQEfcR5cBJKcWO9RUTf28SMSyJ1ozFm0yPmOa2J5MwHylIbVAlc9c\n" +
            "ag3J\n" +
            "=GebS\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";
    private static final String V3Key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "lQHYA2JqgDIAAAEEAOYdcIKFQ5ZWBx0D5DKwMMNFcIhFyqmfDJ0v23ehMxOkXN/o\n" +
            "HO/43+dq6ZqQn0gNw53Tp9no+EmcCYNrZuN0C4Zu8XHSyY6UB+CqzNkz/CwmV10E\n" +
            "dRDipcG1O6scJyy2MWpuOG67til+o+wOLgEkkVkSW8Bl2oqtzVVP4swtKLRZAAUR\n" +
            "AAP+JBiyRqt+DYr8GKE85NBX9nlS6DMaxUYgGKgibR5OSVsJjIjNUtG0sNmODjTN\n" +
            "sPMZqlNln6wS3l7APMWNoStNGc9JG9Puz3eR2W69lPDzhuxuxrHIUBO+3UlEQB/p\n" +
            "N3NPhnwCjh3OWHSMM6rzsX5ExUv0Z4FypnzvMG1x6GRJDVECAO6PyY8NDHsktMVN\n" +
            "HAdgC61iIOz+GbLhNGeikuB+DQpSoyckAF0N5reBxRbyjzNZQ7aVvWpxigUp5OdK\n" +
            "HMK7YcwTAgD275bcqhd+oWHDhyesi6RVswlqGfix48qahf9wOmDkc0nzp8evy/4V\n" +
            "4Qu5zUJGVzi4aEIbFaAnc5lMD9/ydTNjAf485vh4MDFRd3tPvx9mPrHQgaArCBX8\n" +
            "9oImPDk0oaKixwSIFzXeg1qZQeLiwv26Fs8gawWsLVZpR4+zZc1nhZlGnrQpSm9o\n" +
            "biBRLiBTbWl0aCA8MTIzNDUuNjc4OUBjb21wdXNlcnZlLmNvbT6JAJUDBRBiaoAy\n" +
            "VU/izC0otFkBAYIsBACykJ7s82vqCIKewgLpFuqoVGjlfwn9z+G1oa7vr/GxA/mF\n" +
            "Dr4E8rZ1ytUFMUCfzy52FfOtDQUVUeOpAraWQ4JfjXkHuDuZcW2VRh2ctT/hVHG7\n" +
            "1GgOWUBH3EeXASSnFjvUVE39vEjEsidaMxZtMj5jmtieTMB8pSG1QJXPXGoNyQ==\n" +
            "=p7Lr\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    @Test
    public void readV3PublicKey() throws IOException {
        PGPPublicKeyRing cert = PGPainless.readKeyRing().publicKeyRing(V3Cert);
        assertEquals(3, cert.getPublicKey().getVersion());
        assertEquals("John Q. Smith <12345.6789@compuserve.com>", cert.getPublicKey().getUserIDs().next());
    }

    @Test
    public void readV3SecretKey() throws IOException {
        PGPSecretKeyRing key = PGPainless.readKeyRing().secretKeyRing(V3Key);
        assertEquals(3, key.getPublicKey().getVersion());
        assertEquals("John Q. Smith <12345.6789@compuserve.com>", key.getPublicKey().getUserIDs().next());
    }

    @Test
    public void extractV3Cert() throws IOException {
        PGPSecretKeyRing key = PGPainless.readKeyRing().secretKeyRing(V3Key);
        PGPPublicKeyRing cert = PGPainless.readKeyRing().publicKeyRing(V3Cert);

        PGPPublicKeyRing extractedCert = PGPainless.extractCertificate(key);
        assertArrayEquals(cert.getEncoded(), extractedCert.getEncoded());
    }

    @Test
    public void v3FingerprintNotSupported() throws IOException {
        PGPSecretKeyRing key = PGPainless.readKeyRing().secretKeyRing(V3Key);
        assertThrows(IllegalArgumentException.class, () -> OpenPgpFingerprint.of(key));

        PGPPublicKeyRing cert = PGPainless.readKeyRing().publicKeyRing(V3Cert);
        assertThrows(IllegalArgumentException.class, () -> OpenPgpFingerprint.of(cert));
    }
}
