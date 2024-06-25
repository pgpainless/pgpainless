// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package investigations;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;

import java.io.IOException;

public class UnknownKeyVersion {

    @Test
    public void test() throws IOException {
        String KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
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
                "zAYau2VdHqnRJ7QYdxHDiH49jPK4NTMyb/tJh2TiIwcmsIpGzsFKBF2lnPJjCADj\n" +
                "XcBWoBQPy0vnuVEzre6EXaQJYR2WW7aLr/QwDU0Nwcw9QeAlMfbABIzDy32pXfsD\n" +
                "gOaMfOODlAYaW7HQ/iJOLHK8l9+UBh8w3p1/aMYAM5kwP/PK5VaOT4zpXTwLoRO2\n" +
                "IDspzX4GEAsikh5/HA/tINXtoIUr5Kg+S9EsF1JY4KzjamBwYxrAIPWGtkpQilWJ\n" +
                "LjPsj1Wn08ZOVIaJvRXC8wdFSLw6AzrDGfEWeDkXUJUVDy/vtHL7EZL2FenttRRN\n" +
                "8CgFoUQnDzY6SYh6L1tnKF8yfKg2O0DjT72TEH+yFXbGzmRpiCAWbTM2558YitFM\n" +
                "omeu8KeZUCM3dMCYaKZbB/4o/Nl9eDZzWUlHPOpi9UKev5dGgtmopTZUeBSnhLkG\n" +
                "kOKCEXBBZTLdx3UyEi8QV9XJsYBAWRKa19pS33HwtYgK2TNRe5XroJBoL0sjsUnB\n" +
                "Jz1r8rnNt5EX5aOBQPZvG+ih5B5TaYffJsZF376wmIDd6M9dThHj9HH8nui2xNEN\n" +
                "vS5yNksqI8ehIwAj3wwcwqnFkqdliEss7ErYmRlt51fQIs+oCqTFe/YfMkvePW4/\n" +
                "riluP2sJpxStSpD21C83kN1xpSDx1W0jIulE0+EqGk997wbWAfy6Fv2V+JrzYpej\n" +
                "Lt7OHgcZDFppjHpDg1VrUj2GWaLt83uYVKLarC3OHnezwsE+BBgBCgByBYJdpZzy\n" +
                "CRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5v\n" +
                "cmfXHtuoHICRZCURoCNLw5rdWBodqTTk+2bSlujPHAQ57QKbDBYhBNGmbhojsYLJ\n" +
                "mA94jPv8yCoBXnMwAADaBwwAj9uyOR7/bNa1x82F8rroudPrR1FS+IWyjyKLKp3u\n" +
                "tDZZl7gjDQnwp+WH/kXWbA0mgGQIhMw8z2e8CbPpcVufowm0jN4DOZvXwwwVBlSn\n" +
                "YD0N3blVrVaUMevxaR51mUAODVMrCnzfzxdTS84d9iUnVWPOQupafHmvMHW46rXS\n" +
                "go7ckWPScA3WonhOvkdcEXWUkotQYR5/xjPUIJk41khrXwJXnaB1Js7GlEPItn0z\n" +
                "2/buuatcpqrYJiLk4kRV4Cyr4WEJsZ8RXM0yQQM7s9A7uzGMujeSkMsfoMS1+N7b\n" +
                "SzbqgNppJQt1X1sLjwchxmN0iV72KqeDdUcKASNRKFqN1SG3qgw72RH8RczeToY0\n" +
                "NEMSqThFpxlmgRw8OPr8BbOqp6YG7NWprJ+53JCsO6fDN7vAEtjEUMVFXIiC0kss\n" +
                "eU9tP3bmUFMp59f7jamXb6nBvATlT4UXkZb4w/eCIqIhwvCj8LgJvI9w40uFoZxz\n" +
                "qL69eex25sL6yB33k2aiZQ1f\n" +
                "=zrVt\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";

        PGPPublicKeyRing cert = PGPainless.readKeyRing().publicKeyRing(KEY);
    }
}
