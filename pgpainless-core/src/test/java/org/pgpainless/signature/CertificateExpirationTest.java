// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionResult;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.exception.KeyException;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.SubkeyIdentifier;

public class CertificateExpirationTest {

    private static final String data = "Hello World :)";
    OpenPgpV4Fingerprint encryptionSubkey = new OpenPgpV4Fingerprint("1DDCE15F09217CEE2F3B37607C2FAA4DF93C37B2");

    @Test
    public void baseCase() throws IOException, PGPException {
        String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "\n" +
                "xsDNBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
                "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
                "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
                "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
                "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
                "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
                "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
                "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
                "vLIwa3T4CyshfT0AEQEAAc0hQm9iIEJhYmJhZ2UgPGJvYkBvcGVucGdwLmV4YW1w\n" +
                "bGU+wsEOBBMBCgA4AhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE0aZuGiOx\n" +
                "gsmYD3iM+/zIKgFeczAFAl2lnvoACgkQ+/zIKgFeczBvbAv/VNk90a6hG8Od9xTz\n" +
                "XxH5YRFUSGfIA1yjPIVOnKqhMwps2U+sWE3urL+MvjyQRlyRV8oY9IOhQ5Esm6DO\n" +
                "ZYrTnE7qVETm1ajIAP2OFChEc55uH88x/anpPOXOJY7S8jbn3naC9qad75BrZ+3g\n" +
                "9EBUWiy5p8TykP05WSnSxNRt7vFKLfEB4nGkehpwHXOVF0CRNwYle42bg8lpmdXF\n" +
                "DcCZCi+qEbafmTQzkAqyzS3nCh3IAqq6Y0kBuaKLm2tSNUOlZbD+OHYQNZ5Jix7c\n" +
                "ZUzs6Xh4+I55NRWl5smrLq66yOQoFPy9jot/Qxikx/wP3MsAzeGaZSEPc0fHp5G1\n" +
                "6rlGbxQ3vl8/usUV7W+TMEMljgwd5x8POR6HC8EaCDfVnUBCPi/Gv+egLjsIbPJZ\n" +
                "ZEroiE40e6/UoCiQtlpQB5exPJYSd1Q1txCwueih99PHepsDhmUQKiACszNU+RRo\n" +
                "zAYau2VdHqnRJ7QYdxHDiH49jPK4NTMyb/tJh2TiIwcmsIpGzsDNBF2lnPIBDADW\n" +
                "ML9cbGMrp12CtF9b2P6z9TTT74S8iyBOzaSvdGDQY/sUtZXRg21HWamXnn9sSXvI\n" +
                "DEINOQ6A9QxdxoqWdCHrOuW3ofneYXoG+zeKc4dC86wa1TR2q9vW+RMXSO4uImA+\n" +
                "Uzula/6k1DogDf28qhCxMwG/i/m9g1c/0aApuDyKdQ1PXsHHNlgd/Dn6rrd5y2AO\n" +
                "baifV7wIhEJnvqgFXDN2RXGjLeCOHV4Q2WTYPg/S4k1nMXVDwZXrvIsA0YwIMgIT\n" +
                "86Rafp1qKlgPNbiIlC1g9RY/iFaGN2b4Ir6GDohBQSfZW2+LXoPZuVE/wGlQ01rh\n" +
                "827KVZW4lXvqsge+wtnWlszcselGATyzqOK9LdHPdZGzROZYI2e8c+paLNDdVPL6\n" +
                "vdRBUnkCaEkOtl1mr2JpQi5nTU+gTX4IeInC7E+1a9UDF/Y85ybUz8XV8rUnR76U\n" +
                "qVC7KidNepdHbZjjXCt8/Zo+Tec9JNbYNQB/e9ExmDntmlHEsSEQzFwzj8sxH48A\n" +
                "EQEAAcLA9gQYAQoAIBYhBNGmbhojsYLJmA94jPv8yCoBXnMwBQJdpZzyAhsMAAoJ\n" +
                "EPv8yCoBXnMw6f8L/26C34dkjBffTzMj5Bdzm8MtF67OYneJ4TQMw7+41IL4rVcS\n" +
                "KhIhk/3Ud5knaRtP2ef1+5F66h9/RPQOJ5+tvBwhBAcUWSupKnUrdVaZQanYmtSx\n" +
                "cVV2PL9+QEiNN3tzluhaWO//rACxJ+K/ZXQlIzwQVTpNhfGzAaMVV9zpf3u0k14i\n" +
                "tcv6alKY8+rLZvO1wIIeRZLmU0tZDD5HtWDvUV7rIFI1WuoLb+KZgbYn3OWjCPHV\n" +
                "dTrdZ2CqnZbG3SXw6awH9bzRLV9EXkbhIMez0deCVdeo+wFFklh8/5VK2b0vk/+w\n" +
                "qMJxfpa1lHvJLobzOP9fvrswsr92MA2+k901WeISR7qEzcI0Fdg8AyFAExaEK6Vy\n" +
                "jP7SXGLwvfisw34OxuZr3qmx1Sufu4toH3XrB7QJN8XyqqbsGxUCBqWif9RSK4xj\n" +
                "zRTe56iPeiSJJOIciMP9i2ldI+KgLycyeDvGoBj0HCLO3gVaBe4ubVrj5KjhX2PV\n" +
                "NEJd3XZRzaXZE2aAMQ==\n" +
                "=F9yX\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";

        PGPPublicKeyRing cert = PGPainless.readKeyRing().publicKeyRing(CERT);
        EncryptionResult result = encrypt(cert);
        assertTrue(result.getRecipients().contains(new SubkeyIdentifier(cert, encryptionSubkey)));
    }

    @Test
    public void userIdExpired() throws IOException {
        String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "\n" +
                "xsDNBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
                "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
                "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
                "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
                "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
                "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
                "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
                "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
                "vLIwa3T4CyshfT0AEQEAAc0hQm9iIEJhYmJhZ2UgPGJvYkBvcGVucGdwLmV4YW1w\n" +
                "bGU+wsFcBBMBCgCQBYJhD+MLBYkC5nBVBQsJCAcCCRD7/MgqAV5zMEcUAAAAAAAe\n" +
                "ACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmeBlRdIcuQ2Brw4exeLPiI6\n" +
                "auCk+if/VbCgR0ve3oWwnQYVCgkICwIEFgIDAQIXgAIbAwIeARYhBNGmbhojsYLJ\n" +
                "mA94jPv8yCoBXnMwAAAw5wwAo4ebKQfsid8YFCnMzhzYzKNwz8WAybYnPJfY1l4X\n" +
                "fexzvvrKhkSbOY6LTwq27UPVrNsoP5aimLB+w3hjG9aFoGakfSxNhFE7fUsn9ZRh\n" +
                "/cpDTwaIyhUXt4Wbs5wmZtAza058eOG43MyAvJepVvMhUCSXAZMvLjNEn5chmW6r\n" +
                "1Wnv10phK64flHvFq4FQooofPf03TQmKsw0Sust94MKzoemcgkHzjNGnqls/Ni9o\n" +
                "+g3ROX7+xXVWU4e3V8ooMtDtS03Z9jq+CsoOldco1mkYP8hxa/UNBdotdK1x1mnT\n" +
                "ofg27H/B3jK0PcetvMS+66zMEFWYDLLignKG/jXXhTbx3/7Un/CgVQnFAipOpcMT\n" +
                "GlVMqrsYNk0epwy8xVT0osTIbK/CCxle+1cg9upO1j8twW+AkGledIZDWPUXhAZj\n" +
                "oJq8l3mwaHC/vY0QJRistwCED3spcHUQ26WykbhhV1bxAl6pUPKCA3nMT6vj768l\n" +
                "2S87cqWEijd32IeHQy5pzqSdzsDNBF2lnPIBDADWML9cbGMrp12CtF9b2P6z9TTT\n" +
                "74S8iyBOzaSvdGDQY/sUtZXRg21HWamXnn9sSXvIDEINOQ6A9QxdxoqWdCHrOuW3\n" +
                "ofneYXoG+zeKc4dC86wa1TR2q9vW+RMXSO4uImA+Uzula/6k1DogDf28qhCxMwG/\n" +
                "i/m9g1c/0aApuDyKdQ1PXsHHNlgd/Dn6rrd5y2AObaifV7wIhEJnvqgFXDN2RXGj\n" +
                "LeCOHV4Q2WTYPg/S4k1nMXVDwZXrvIsA0YwIMgIT86Rafp1qKlgPNbiIlC1g9RY/\n" +
                "iFaGN2b4Ir6GDohBQSfZW2+LXoPZuVE/wGlQ01rh827KVZW4lXvqsge+wtnWlszc\n" +
                "selGATyzqOK9LdHPdZGzROZYI2e8c+paLNDdVPL6vdRBUnkCaEkOtl1mr2JpQi5n\n" +
                "TU+gTX4IeInC7E+1a9UDF/Y85ybUz8XV8rUnR76UqVC7KidNepdHbZjjXCt8/Zo+\n" +
                "Tec9JNbYNQB/e9ExmDntmlHEsSEQzFwzj8sxH48AEQEAAcLA9gQYAQoAIBYhBNGm\n" +
                "bhojsYLJmA94jPv8yCoBXnMwBQJdpZzyAhsMAAoJEPv8yCoBXnMw6f8L/26C34dk\n" +
                "jBffTzMj5Bdzm8MtF67OYneJ4TQMw7+41IL4rVcSKhIhk/3Ud5knaRtP2ef1+5F6\n" +
                "6h9/RPQOJ5+tvBwhBAcUWSupKnUrdVaZQanYmtSxcVV2PL9+QEiNN3tzluhaWO//\n" +
                "rACxJ+K/ZXQlIzwQVTpNhfGzAaMVV9zpf3u0k14itcv6alKY8+rLZvO1wIIeRZLm\n" +
                "U0tZDD5HtWDvUV7rIFI1WuoLb+KZgbYn3OWjCPHVdTrdZ2CqnZbG3SXw6awH9bzR\n" +
                "LV9EXkbhIMez0deCVdeo+wFFklh8/5VK2b0vk/+wqMJxfpa1lHvJLobzOP9fvrsw\n" +
                "sr92MA2+k901WeISR7qEzcI0Fdg8AyFAExaEK6VyjP7SXGLwvfisw34OxuZr3qmx\n" +
                "1Sufu4toH3XrB7QJN8XyqqbsGxUCBqWif9RSK4xjzRTe56iPeiSJJOIciMP9i2ld\n" +
                "I+KgLycyeDvGoBj0HCLO3gVaBe4ubVrj5KjhX2PVNEJd3XZRzaXZE2aAMQ==\n" +
                "=Bn/c\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";

        PGPPublicKeyRing cert = PGPainless.readKeyRing().publicKeyRing(CERT);
        assertThrows(KeyException.ExpiredKeyException.class, () -> encrypt(cert));
    }

    private EncryptionResult encrypt(PGPPublicKeyRing certificate) throws PGPException, IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(ProducerOptions.encrypt(
                        EncryptionOptions.encryptCommunications()
                                .addRecipient(certificate)
                ));

        ByteArrayInputStream dataIn = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
        Streams.pipeAll(dataIn, encryptionStream);

        encryptionStream.close();
        EncryptionResult result = encryptionStream.getResult();
        return result;
    }
}
