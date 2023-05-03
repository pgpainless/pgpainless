// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;

/**
 * Regression test for BC handling signatures of unknown version.
 * This test makes sure that BC properly ignores unknown signature version.
 */
public class IgnoreUnknownSignatureVersionsTest {

    private static final String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: Bob's OpenPGP certificate\n" +
            "\n" +
            "mQGNBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
            "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
            "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
            "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
            "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
            "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
            "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
            "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
            "vLIwa3T4CyshfT0AEQEAAbQhQm9iIEJhYmJhZ2UgPGJvYkBvcGVucGdwLmV4YW1w\n" +
            "bGU+iQHOBBMBCgA4AhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE0aZuGiOx\n" +
            "gsmYD3iM+/zIKgFeczAFAl2lnvoACgkQ+/zIKgFeczBvbAv/VNk90a6hG8Od9xTz\n" +
            "XxH5YRFUSGfIA1yjPIVOnKqhMwps2U+sWE3urL+MvjyQRlyRV8oY9IOhQ5Esm6DO\n" +
            "ZYrTnE7qVETm1ajIAP2OFChEc55uH88x/anpPOXOJY7S8jbn3naC9qad75BrZ+3g\n" +
            "9EBUWiy5p8TykP05WSnSxNRt7vFKLfEB4nGkehpwHXOVF0CRNwYle42bg8lpmdXF\n" +
            "DcCZCi+qEbafmTQzkAqyzS3nCh3IAqq6Y0kBuaKLm2tSNUOlZbD+OHYQNZ5Jix7c\n" +
            "ZUzs6Xh4+I55NRWl5smrLq66yOQoFPy9jot/Qxikx/wP3MsAzeGaZSEPc0fHp5G1\n" +
            "6rlGbxQ3vl8/usUV7W+TMEMljgwd5x8POR6HC8EaCDfVnUBCPi/Gv+egLjsIbPJZ\n" +
            "ZEroiE40e6/UoCiQtlpQB5exPJYSd1Q1txCwueih99PHepsDhmUQKiACszNU+RRo\n" +
            "zAYau2VdHqnRJ7QYdxHDiH49jPK4NTMyb/tJh2TiIwcmsIpGuQGNBF2lnPIBDADW\n" +
            "ML9cbGMrp12CtF9b2P6z9TTT74S8iyBOzaSvdGDQY/sUtZXRg21HWamXnn9sSXvI\n" +
            "DEINOQ6A9QxdxoqWdCHrOuW3ofneYXoG+zeKc4dC86wa1TR2q9vW+RMXSO4uImA+\n" +
            "Uzula/6k1DogDf28qhCxMwG/i/m9g1c/0aApuDyKdQ1PXsHHNlgd/Dn6rrd5y2AO\n" +
            "baifV7wIhEJnvqgFXDN2RXGjLeCOHV4Q2WTYPg/S4k1nMXVDwZXrvIsA0YwIMgIT\n" +
            "86Rafp1qKlgPNbiIlC1g9RY/iFaGN2b4Ir6GDohBQSfZW2+LXoPZuVE/wGlQ01rh\n" +
            "827KVZW4lXvqsge+wtnWlszcselGATyzqOK9LdHPdZGzROZYI2e8c+paLNDdVPL6\n" +
            "vdRBUnkCaEkOtl1mr2JpQi5nTU+gTX4IeInC7E+1a9UDF/Y85ybUz8XV8rUnR76U\n" +
            "qVC7KidNepdHbZjjXCt8/Zo+Tec9JNbYNQB/e9ExmDntmlHEsSEQzFwzj8sxH48A\n" +
            "EQEAAYkBtgQYAQoAIBYhBNGmbhojsYLJmA94jPv8yCoBXnMwBQJdpZzyAhsMAAoJ\n" +
            "EPv8yCoBXnMw6f8L/26C34dkjBffTzMj5Bdzm8MtF67OYneJ4TQMw7+41IL4rVcS\n" +
            "KhIhk/3Ud5knaRtP2ef1+5F66h9/RPQOJ5+tvBwhBAcUWSupKnUrdVaZQanYmtSx\n" +
            "cVV2PL9+QEiNN3tzluhaWO//rACxJ+K/ZXQlIzwQVTpNhfGzAaMVV9zpf3u0k14i\n" +
            "tcv6alKY8+rLZvO1wIIeRZLmU0tZDD5HtWDvUV7rIFI1WuoLb+KZgbYn3OWjCPHV\n" +
            "dTrdZ2CqnZbG3SXw6awH9bzRLV9EXkbhIMez0deCVdeo+wFFklh8/5VK2b0vk/+w\n" +
            "qMJxfpa1lHvJLobzOP9fvrswsr92MA2+k901WeISR7qEzcI0Fdg8AyFAExaEK6Vy\n" +
            "jP7SXGLwvfisw34OxuZr3qmx1Sufu4toH3XrB7QJN8XyqqbsGxUCBqWif9RSK4xj\n" +
            "zRTe56iPeiSJJOIciMP9i2ldI+KgLycyeDvGoBj0HCLO3gVaBe4ubVrj5KjhX2PV\n" +
            "NEJd3XZRzaXZE2aAMQ==\n" +
            "=NXei\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";
    private static final String message = "Hello World :)";

    private static PGPPublicKeyRing cert;
    static {
        try {
            cert = PGPainless.readKeyRing().publicKeyRing(CERT);
        } catch (IOException e) {
            fail("Cannot parse certificate.", e);
        }
    }

    @Test
    public void baseCase() throws IOException, PGPException {
        String BASE_CASE = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsE7BAABCgBvBYJhaVoTCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmcQWMonyHF4Gcry0TOPKj/RQyhVoSI+1C31rXHHBcxI\n" +
                "yxYhBNGmbhojsYLJmA94jPv8yCoBXnMwAAB7RwwAo+/P0/foJZp0/4yZWbBu/uNC\n" +
                "0afvqv/tfcLVX6tZEmXkh6DfCtDwqX0vWrwAJuqtLUC8RvUDj7X4vi90/LhU2GUs\n" +
                "+h+eZoQ3VwZ8jmfisQs7FUhbPOURZhRoS4UT8w7Le3pLodj5vAcaB6VvZP7SZ2Ls\n" +
                "iNob9J0godpjlkGGWGqjWl0AO1kVvaNJTXpNhwpCRZyad8wUgri5QtrHWzRo4FBb\n" +
                "JzrbJqWaS1FaqMCuPwcpq0KLsn4v6i4sD6Vy3HOaF29+avWNawnMLB/92csl4blq\n" +
                "J20D2sKGUGcJpmLdiupnDdsHWU1jSpUvoUv+viE1RDqBFDQaNkUxdv5DhDOSRcwI\n" +
                "a8Upx9lG8ol0uuDE4jieie4wuNq41jVRWJ55aJ46zO9QPifq59SMcRj8uN8byRKz\n" +
                "Wdg/ngldiePCjg2RQztgb6Hsut7xeYYhuAYQ8m1+vLCnS8tRnCqhAqxdW51uSfIq\n" +
                "xKukH+bioF/+baqBu1AlXmNVou1uiXJaDzZ6wQfBwsE7BAABCgBvBYJhaVoTCRD7\n" +
                "/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmcQ\n" +
                "WMonyHF4Gcry0TOPKj/RQyhVoSI+1C31rXHHBcxIyxYhBNGmbhojsYLJmA94jPv8\n" +
                "yCoBXnMwAAB7RwwAo+/P0/foJZp0/4yZWbBu/uNC0afvqv/tfcLVX6tZEmXkh6Df\n" +
                "CtDwqX0vWrwAJuqtLUC8RvUDj7X4vi90/LhU2GUs+h+eZoQ3VwZ8jmfisQs7FUhb\n" +
                "POURZhRoS4UT8w7Le3pLodj5vAcaB6VvZP7SZ2LsiNob9J0godpjlkGGWGqjWl0A\n" +
                "O1kVvaNJTXpNhwpCRZyad8wUgri5QtrHWzRo4FBbJzrbJqWaS1FaqMCuPwcpq0KL\n" +
                "sn4v6i4sD6Vy3HOaF29+avWNawnMLB/92csl4blqJ20D2sKGUGcJpmLdiupnDdsH\n" +
                "WU1jSpUvoUv+viE1RDqBFDQaNkUxdv5DhDOSRcwIa8Upx9lG8ol0uuDE4jieie4w\n" +
                "uNq41jVRWJ55aJ46zO9QPifq59SMcRj8uN8byRKzWdg/ngldiePCjg2RQztgb6Hs\n" +
                "ut7xeYYhuAYQ8m1+vLCnS8tRnCqhAqxdW51uSfIqxKukH+bioF/+baqBu1AlXmNV\n" +
                "ou1uiXJaDzZ6wQfB\n" +
                "=uHRc\n" +
                "-----END PGP SIGNATURE-----\n";
        OpenPgpMetadata metadata = verifySignature(cert, BASE_CASE);

        assertTrue(metadata.isVerified());
    }

    @Test
    public void detached_SIG4_SIG23() throws PGPException, IOException {
        String SIG4SIG23 = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsE7BAABCgBvBYJhaVoTCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmcQWMonyHF4Gcry0TOPKj/RQyhVoSI+1C31rXHHBcxI\n" +
                "yxYhBNGmbhojsYLJmA94jPv8yCoBXnMwAAB7RwwAo+/P0/foJZp0/4yZWbBu/uNC\n" +
                "0afvqv/tfcLVX6tZEmXkh6DfCtDwqX0vWrwAJuqtLUC8RvUDj7X4vi90/LhU2GUs\n" +
                "+h+eZoQ3VwZ8jmfisQs7FUhbPOURZhRoS4UT8w7Le3pLodj5vAcaB6VvZP7SZ2Ls\n" +
                "iNob9J0godpjlkGGWGqjWl0AO1kVvaNJTXpNhwpCRZyad8wUgri5QtrHWzRo4FBb\n" +
                "JzrbJqWaS1FaqMCuPwcpq0KLsn4v6i4sD6Vy3HOaF29+avWNawnMLB/92csl4blq\n" +
                "J20D2sKGUGcJpmLdiupnDdsHWU1jSpUvoUv+viE1RDqBFDQaNkUxdv5DhDOSRcwI\n" +
                "a8Upx9lG8ol0uuDE4jieie4wuNq41jVRWJ55aJ46zO9QPifq59SMcRj8uN8byRKz\n" +
                "Wdg/ngldiePCjg2RQztgb6Hsut7xeYYhuAYQ8m1+vLCnS8tRnCqhAqxdW51uSfIq\n" +
                "xKukH+bioF/+baqBu1AlXmNVou1uiXJaDzZ6wQfBwsE7FwABCgBvBYJhaVoTCRD7\n" +
                "/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmcQ\n" +
                "WMonyHF4Gcry0TOPKj/RQyhVoSI+1C31rXHHBcxIyxYhBNGmbhojsYLJmA94jPv8\n" +
                "yCoBXnMwAAB7RwwAo+/P0/foJZp0/4yZWbBu/uNC0afvqv/tfcLVX6tZEmXkh6Df\n" +
                "CtDwqX0vWrwAJuqtLUC8RvUDj7X4vi90/LhU2GUs+h+eZoQ3VwZ8jmfisQs7FUhb\n" +
                "POURZhRoS4UT8w7Le3pLodj5vAcaB6VvZP7SZ2LsiNob9J0godpjlkGGWGqjWl0A\n" +
                "O1kVvaNJTXpNhwpCRZyad8wUgri5QtrHWzRo4FBbJzrbJqWaS1FaqMCuPwcpq0KL\n" +
                "sn4v6i4sD6Vy3HOaF29+avWNawnMLB/92csl4blqJ20D2sKGUGcJpmLdiupnDdsH\n" +
                "WU1jSpUvoUv+viE1RDqBFDQaNkUxdv5DhDOSRcwIa8Upx9lG8ol0uuDE4jieie4w\n" +
                "uNq41jVRWJ55aJ46zO9QPifq59SMcRj8uN8byRKzWdg/ngldiePCjg2RQztgb6Hs\n" +
                "ut7xeYYhuAYQ8m1+vLCnS8tRnCqhAqxdW51uSfIqxKukH+bioF/+baqBu1AlXmNV\n" +
                "ou1uiXJaDzZ6wQfB\n" +
                "=/JL1\n" +
                "-----END PGP SIGNATURE-----\n";
        OpenPgpMetadata metadata = verifySignature(cert, SIG4SIG23);

        assertTrue(metadata.isVerified());
    }

    @Test
    public void detached_SIG23_SIG4() throws PGPException, IOException {
        String SIG23SIG4 = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsE7FwABCgBvBYJhaVoTCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmcQWMonyHF4Gcry0TOPKj/RQyhVoSI+1C31rXHHBcxI\n" +
                "yxYhBNGmbhojsYLJmA94jPv8yCoBXnMwAAB7RwwAo+/P0/foJZp0/4yZWbBu/uNC\n" +
                "0afvqv/tfcLVX6tZEmXkh6DfCtDwqX0vWrwAJuqtLUC8RvUDj7X4vi90/LhU2GUs\n" +
                "+h+eZoQ3VwZ8jmfisQs7FUhbPOURZhRoS4UT8w7Le3pLodj5vAcaB6VvZP7SZ2Ls\n" +
                "iNob9J0godpjlkGGWGqjWl0AO1kVvaNJTXpNhwpCRZyad8wUgri5QtrHWzRo4FBb\n" +
                "JzrbJqWaS1FaqMCuPwcpq0KLsn4v6i4sD6Vy3HOaF29+avWNawnMLB/92csl4blq\n" +
                "J20D2sKGUGcJpmLdiupnDdsHWU1jSpUvoUv+viE1RDqBFDQaNkUxdv5DhDOSRcwI\n" +
                "a8Upx9lG8ol0uuDE4jieie4wuNq41jVRWJ55aJ46zO9QPifq59SMcRj8uN8byRKz\n" +
                "Wdg/ngldiePCjg2RQztgb6Hsut7xeYYhuAYQ8m1+vLCnS8tRnCqhAqxdW51uSfIq\n" +
                "xKukH+bioF/+baqBu1AlXmNVou1uiXJaDzZ6wQfBwsE7BAABCgBvBYJhaVoTCRD7\n" +
                "/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmcQ\n" +
                "WMonyHF4Gcry0TOPKj/RQyhVoSI+1C31rXHHBcxIyxYhBNGmbhojsYLJmA94jPv8\n" +
                "yCoBXnMwAAB7RwwAo+/P0/foJZp0/4yZWbBu/uNC0afvqv/tfcLVX6tZEmXkh6Df\n" +
                "CtDwqX0vWrwAJuqtLUC8RvUDj7X4vi90/LhU2GUs+h+eZoQ3VwZ8jmfisQs7FUhb\n" +
                "POURZhRoS4UT8w7Le3pLodj5vAcaB6VvZP7SZ2LsiNob9J0godpjlkGGWGqjWl0A\n" +
                "O1kVvaNJTXpNhwpCRZyad8wUgri5QtrHWzRo4FBbJzrbJqWaS1FaqMCuPwcpq0KL\n" +
                "sn4v6i4sD6Vy3HOaF29+avWNawnMLB/92csl4blqJ20D2sKGUGcJpmLdiupnDdsH\n" +
                "WU1jSpUvoUv+viE1RDqBFDQaNkUxdv5DhDOSRcwIa8Upx9lG8ol0uuDE4jieie4w\n" +
                "uNq41jVRWJ55aJ46zO9QPifq59SMcRj8uN8byRKzWdg/ngldiePCjg2RQztgb6Hs\n" +
                "ut7xeYYhuAYQ8m1+vLCnS8tRnCqhAqxdW51uSfIqxKukH+bioF/+baqBu1AlXmNV\n" +
                "ou1uiXJaDzZ6wQfB\n" +
                "=Yc8d\n" +
                "-----END PGP SIGNATURE-----\n";
        OpenPgpMetadata metadata = verifySignature(cert, SIG23SIG4);

        assertTrue(metadata.isVerified());
    }

    private OpenPgpMetadata verifySignature(PGPPublicKeyRing cert, String BASE_CASE) throws PGPException, IOException {
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify().onInputStream(new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)))
                .withOptions(new ConsumerOptions()
                        .addVerificationCert(cert)
                        .addVerificationOfDetachedSignatures(new ByteArrayInputStream(BASE_CASE.getBytes(StandardCharsets.UTF_8))));

        Streams.drain(decryptionStream);
        decryptionStream.close();

        return decryptionStream.getResult();
    }
}
