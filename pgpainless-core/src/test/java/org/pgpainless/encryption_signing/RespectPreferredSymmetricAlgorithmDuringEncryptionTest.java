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
package org.pgpainless.encryption_signing;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;

public class RespectPreferredSymmetricAlgorithmDuringEncryptionTest {

    @Test
    public void onlyAES128() throws IOException, PGPException {
        // Key has [AES128] as preferred symm. algo on latest user-id cert
        String key = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
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
                "bGU+wsFTBBMBCgCHBYJgq9xiAgsHCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmdNgMRYEX46LCBpUimr3zIek/oZSVT+EcdR\n" +
                "Y4Rno2QSzQYVCgkICwIEFgIDAQIXgAIbAwIeARYhBNGmbhojsYLJmA94jPv8yCoB\n" +
                "XnMwAADsbAv/bpWiiT47IuGxe11aReA2ThLy8jwafKEOrHxiUvyJdG/s7Bn0QtqM\n" +
                "9G/16QDOWbSiXMD2vJYB7ml7oYlSxDS6oVd1bfGRsRbRr6N/wCTMXBaB4TsYqbcl\n" +
                "NOznt+RSRIWYKCHJDDEdBvuJmf+Mmi09NVHOupjOt51WiVWmm5GpVUl5789yBvN8\n" +
                "iei7I85KB/bXV0CfUgw9jx8BwAANPri+l4Br5fKMoheguHBm8BLPzWCfvCxZORq5\n" +
                "Nd9wLhEe+/7M2Y8AGzfn88XgGUXNOh7y8ZSD9AjK14UQilUg8IrYm7oJik29bVyh\n" +
                "UyY7sAJB5B7TxjE374krsOkl+lXe6bWDguJhrjIR0S0OWXmFpt06uDIOuI+f6ach\n" +
                "m0kbUELUiQOQ+4i17mph11WiQczT2iS7preLpI5cjQd1cIQczOjxDaRvNPvtxYne\n" +
                "ijUCkQzPwGAAcuXRe94wW3VtimwswLM5wmhzCgjv7uZMvEg6lHpVRWrJA6oXj6f1\n" +
                "MnufQ5Li2/zMwsEOBBMBCgA4AhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE\n" +
                "0aZuGiOxgsmYD3iM+/zIKgFeczAFAl2lnvoACgkQ+/zIKgFeczBvbAv/VNk90a6h\n" +
                "G8Od9xTzXxH5YRFUSGfIA1yjPIVOnKqhMwps2U+sWE3urL+MvjyQRlyRV8oY9IOh\n" +
                "Q5Esm6DOZYrTnE7qVETm1ajIAP2OFChEc55uH88x/anpPOXOJY7S8jbn3naC9qad\n" +
                "75BrZ+3g9EBUWiy5p8TykP05WSnSxNRt7vFKLfEB4nGkehpwHXOVF0CRNwYle42b\n" +
                "g8lpmdXFDcCZCi+qEbafmTQzkAqyzS3nCh3IAqq6Y0kBuaKLm2tSNUOlZbD+OHYQ\n" +
                "NZ5Jix7cZUzs6Xh4+I55NRWl5smrLq66yOQoFPy9jot/Qxikx/wP3MsAzeGaZSEP\n" +
                "c0fHp5G16rlGbxQ3vl8/usUV7W+TMEMljgwd5x8POR6HC8EaCDfVnUBCPi/Gv+eg\n" +
                "LjsIbPJZZEroiE40e6/UoCiQtlpQB5exPJYSd1Q1txCwueih99PHepsDhmUQKiAC\n" +
                "szNU+RRozAYau2VdHqnRJ7QYdxHDiH49jPK4NTMyb/tJh2TiIwcmsIpGzsDNBF2l\n" +
                "nPIBDADWML9cbGMrp12CtF9b2P6z9TTT74S8iyBOzaSvdGDQY/sUtZXRg21HWamX\n" +
                "nn9sSXvIDEINOQ6A9QxdxoqWdCHrOuW3ofneYXoG+zeKc4dC86wa1TR2q9vW+RMX\n" +
                "SO4uImA+Uzula/6k1DogDf28qhCxMwG/i/m9g1c/0aApuDyKdQ1PXsHHNlgd/Dn6\n" +
                "rrd5y2AObaifV7wIhEJnvqgFXDN2RXGjLeCOHV4Q2WTYPg/S4k1nMXVDwZXrvIsA\n" +
                "0YwIMgIT86Rafp1qKlgPNbiIlC1g9RY/iFaGN2b4Ir6GDohBQSfZW2+LXoPZuVE/\n" +
                "wGlQ01rh827KVZW4lXvqsge+wtnWlszcselGATyzqOK9LdHPdZGzROZYI2e8c+pa\n" +
                "LNDdVPL6vdRBUnkCaEkOtl1mr2JpQi5nTU+gTX4IeInC7E+1a9UDF/Y85ybUz8XV\n" +
                "8rUnR76UqVC7KidNepdHbZjjXCt8/Zo+Tec9JNbYNQB/e9ExmDntmlHEsSEQzFwz\n" +
                "j8sxH48AEQEAAcLA9gQYAQoAIBYhBNGmbhojsYLJmA94jPv8yCoBXnMwBQJdpZzy\n" +
                "AhsMAAoJEPv8yCoBXnMw6f8L/26C34dkjBffTzMj5Bdzm8MtF67OYneJ4TQMw7+4\n" +
                "1IL4rVcSKhIhk/3Ud5knaRtP2ef1+5F66h9/RPQOJ5+tvBwhBAcUWSupKnUrdVaZ\n" +
                "QanYmtSxcVV2PL9+QEiNN3tzluhaWO//rACxJ+K/ZXQlIzwQVTpNhfGzAaMVV9zp\n" +
                "f3u0k14itcv6alKY8+rLZvO1wIIeRZLmU0tZDD5HtWDvUV7rIFI1WuoLb+KZgbYn\n" +
                "3OWjCPHVdTrdZ2CqnZbG3SXw6awH9bzRLV9EXkbhIMez0deCVdeo+wFFklh8/5VK\n" +
                "2b0vk/+wqMJxfpa1lHvJLobzOP9fvrswsr92MA2+k901WeISR7qEzcI0Fdg8AyFA\n" +
                "ExaEK6VyjP7SXGLwvfisw34OxuZr3qmx1Sufu4toH3XrB7QJN8XyqqbsGxUCBqWi\n" +
                "f9RSK4xjzRTe56iPeiSJJOIciMP9i2ldI+KgLycyeDvGoBj0HCLO3gVaBe4ubVrj\n" +
                "5KjhX2PVNEJd3XZRzaXZE2aAMQ==\n" +
                "=d5ke\n" +
                "-----END PGP ARMORED FILE-----\n";

        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(key);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign().onOutputStream(out)
                .withOptions(
                        ProducerOptions.encrypt(new EncryptionOptions()
                                .addRecipient(publicKeys)
                        ));

        encryptionStream.close();
        assertEquals(SymmetricKeyAlgorithm.AES_128, encryptionStream.getResult().getEncryptionAlgorithm());
    }
}
