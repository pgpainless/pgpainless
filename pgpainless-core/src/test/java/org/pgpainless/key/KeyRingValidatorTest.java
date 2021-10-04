/*
 * Copyright 2021 Paul Schaub.
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
package org.pgpainless.key;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

import org.bouncycastle.bcpg.attr.ImageAttribute;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVectorGenerator;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.ArmorUtils;
import org.pgpainless.util.CollectionUtils;
import org.pgpainless.util.DateUtil;

public class KeyRingValidatorTest {

    @Test
    public void testRevokedSubkey() throws IOException {
        String key = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "xsBNBFpJegABCAC1ePFquP0135m8DYhcybhv7l+ecojitFOd/jRM7hCczIqKgalD\n" +
                "1Ro1gNr3VmH6FjRIKIvGT+sOzCKne1v3KyAAPoxtwxjkATTKdOGo15I6v5ZjmO1d\n" +
                "rLQOLSt1TF7XbQSt+ns6PUZWJL907DvECUU5b9FkNUqfQ14QqY+gi7MOyAQez3b7\n" +
                "Pg5Cyz/kVWQ6TSMW/myDEDEertQ4rDBsptEDFHCC2+iF4hO2LqfiCriu5qyLcKCQ\n" +
                "pd6dEuwJQ/jjT0D9A9Fwf+i04x6ZPKSU9oNAWqn8OSAq3/0B/hu9V+0U0iHPnJxe\n" +
                "quykvJk7maxhiGhxBWYXTvDJmoon0NOles7LABEBAAHCwHwEHwEKAA8Fgl4L4QAC\n" +
                "FQoCmwMCHgEAIQkQaE+tYtwDj7sWIQTy0VCk/piSXVHpFTloT61i3AOPu8ffB/9Q\n" +
                "60dg60qhA2rPnd/1dCL2B+c8RWnq44PpijE3gA1RQvcRQE5jNzMSo/MnG0mSL5wH\n" +
                "eTsjSd/DRI3nHP06rs6Qub11NoKhNuya3maz9gyzeZMc/jNib83/BzFCrxsSQm+9\n" +
                "WHurxXeWXOPMLZs3xS/jG0EDtCJ2Fm4UF19fcIydwN/ssF4NGpfCY82+wTSx4joI\n" +
                "3cRKObCFJaaBgG5nl+eFr7cfjEIuqCJCaQsXiqBe7d6V3KqN18t+CgSaybMZXcys\n" +
                "Q/USxEkLhIB2pOZwcz4E3TTFgxRAxcr4cs4Bd2PRz3Z5FKTzo0ma/Ft0UfFJR+fC\n" +
                "cs55+n6kC9K0y/E7BY2hwsB8BB8BCgAPBYJaSXoAAhUKApsDAh4BACEJEGhPrWLc\n" +
                "A4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwDj7uqDQf7BqTD6GNTwXPOt/0kHQPYmbdI\n" +
                "tX+pWP+o3jaB6VTHDXcn27bttA5M82EXZfae4+bC1dMB+1uLal4ciVgO9ImJC9Nw\n" +
                "s5fc3JH4R5uuSvpjzjudkJsGu3cAKE3hwiT93Mi6t6ENpLCDSxqxzAmfoOQbVJYW\n" +
                "Y7gP7Z4Cj0IAP29aprEc0JWoMjHKpKgYF6u0sWgHWBuEXk/6o6GYb2HZYK4ycpY2\n" +
                "WXKgVhy7/iQDYO1FOfcWQXHVGLn8OzILjobKohNenTT20ZhAASi3LUDSDMTQfxSS\n" +
                "Vt0nhzWuXJJ4R8PzUVeRJ0A0oMyjZVHivHC6GwMsiQuSUTx8e/GnOByOqfGne80S\n" +
                "anVsaWV0QGV4YW1wbGUub3JnwsBzBBMBCgAGBYJaSXoAACEJEGhPrWLcA4+7FiEE\n" +
                "8tFQpP6Ykl1R6RU5aE+tYtwDj7tDfQf+PnxsIFu/0juKBUjjtAYfRzkrrYtMepPj\n" +
                "taTvGfo1SzUkX/6F/GjdSeVg5Iq6YcBrj8c+cB3EoZpHnScTgWQHwceWQLd9Hhbg\n" +
                "TrUNvW1eg2CVzN0RBuYMtWu9JM4pH7ssJW1NmN+/N9B67qb2y+JfBwH/la508NzC\n" +
                "rl3xWTxjT5wNy+FGkNZg23s/0qlO2uxCjc+mRAuAlp5EmTOVWOIBbM0xttjBOx39\n" +
                "ZmWWQKJZ0nrFjK1jppHqazwWWNX7RHkK81tlbSUtOPoTIJDz38NaiyMcZH3p9okN\n" +
                "3DU4XtF+oE18M+Z/E0xUQmumbkajFzcUjmd7enozP5BnGESzdNS5Xc7ATQRaSsuA\n" +
                "AQgAykb8tqlWXtqHGGkBqAq3EnpmvBqrKvqejjtZKAXqEszJ9NlibCGUuLwnNOVO\n" +
                "R/hcOUlOGH+cyMcApBWJB+7d/83K1eCCdv88nDFVav7hKLKlEBbZJNHgHpJ313pl\n" +
                "etzCR4x3STEISrEtO71l2HBdrKSYXaxGgILxYwcSi3i2EjzxRDy+0zyy8s7d+OD5\n" +
                "ShFYexgSrKH3Xx1cxQAJzGGJVx75HHU9GVh3xHwJ7nDm26KzHegG2XPIBXJ2z8vm\n" +
                "sSVTWyj0AjT4kVVapN0f84AKKjyQ7fguCzXGHFV9jmxDx+YH+9HhjIrHSzbDx6+4\n" +
                "wyRsxj7Su+hu/bogJ28nnbTzQwARAQABwsCTBCgBCgAmBYJcKq2AHx3IVW5rbm93\n" +
                "biByZXZvY2F0aW9uIHJlYXNvbiAyMDAAIQkQaE+tYtwDj7sWIQTy0VCk/piSXVHp\n" +
                "FTloT61i3AOPu6RDCACgqNPoLWPsjWDyZxvF8MyYTB3JivI7RVf8W6mNJTxMDD69\n" +
                "iWwiC0F6R8M3ljk8vc85C6tQ8iWPVT6cGHhFgQn14a1MYpgyVTTdwjbqvjxmPeyS\n" +
                "We31yZGz54dAsONnrWScO4ZdKVTtKhu115KELiPmguoN/JwG+OIbgvKvzQX+8D4M\n" +
                "Gl823A6Ua8/zJm/TAOQolo6X9Sqr9bO1v/z3ecuYkuNeGhQOC3/VQ0TH2xRbmykD\n" +
                "5XbgffPi0sjg2ZRrDikg/W+40gxW+oHxQ6ZIaIn/OFooj7xooH+jn++f8W8faEk5\n" +
                "pLOoCwsX0SucDbGvt85D1DhOUD9H0CEkaZbO+113wsGsBBgBCgAJBYJeC+EAApsC\n" +
                "AVcJEGhPrWLcA4+7wHSgBBkBCgAGBYJeC+EAACEJEEpyNKOhITplFiEEUXksDkji\n" +
                "/alOk7kRSnI0o6EhOmWnSQgAiu/zdEmHf6Wbwfbs/c6FObfPxGuzLkQr4fZKcqK8\n" +
                "1MtR1mh1WVLJRgXW4u8cHtZyH5pThngMcUiyzWsa0g6Jaz8w6sr/Wv3e1qdTCITs\n" +
                "kMrWCDaoDhD2teAjmWuk9u8ZBPJ7xhme+Q/UQ90xomQ/NdCJafirk2Ds92p7N7RK\n" +
                "SES1KywBhfONJbPw1TdZ9Mts+DGjkucYbe+ZzPxrLpWXur1BSGEqBtTAGW3dS/xp\n" +
                "wBYNlhasXHjYMr4HeIYYYOx+oR5JgDYoVfp2k0DwK/QXogbja+/Vjv+LrXdNY0t1\n" +
                "bA35FNnl637M8iCNrXvIoRFARbNyge8c/jSWGPLB/tIyNhYhBPLRUKT+mJJdUekV\n" +
                "OWhPrWLcA4+7FLwIAK1GngNMnruxWM4EoghKTSmKNrd6p/d3Wsd+y2019A7Nz+4O\n" +
                "ydkEDvmNVVhlUcfgOf2L6Bf63wdN0ho+ODhCuNSqHe6NL1NhdITbMGnDdKb57IIB\n" +
                "9CuJFpILn9LZ1Ei6JPEpmpiSEaL+VJt1fMnfc8jtF8N3WcRVfJsq1aslXe8Npg70\n" +
                "9YVgm2OXsNWgktl9fciu4ENTybQGjpN9WTa1aU1nkko6NUoIfjtM+PO4VU7x00M+\n" +
                "dTJsYGhnc96EtT8EfSAIFBKZRAkMBFhEcdkxa8hCKI3+nyI3gTq0TcFST3wy05Am\n" +
                "oV7wlgzUAMsW7MV2NpG7fJul2Q7puKw+udBUc0TCwawEGAEKAAkFglro/4ACmwIB\n" +
                "VwkQaE+tYtwDj7vAdKAEGQEKAAYFglro/4AAIQkQSnI0o6EhOmUWIQRReSwOSOL9\n" +
                "qU6TuRFKcjSjoSE6ZeFHB/92jhUTXrEgho6DYhmVFuXa3NGhAjIyZo3yYHMoL9aZ\n" +
                "3DUyjxhAyRDpI2CrahQ4JsPhej2m+3fHWa34/tb5mpHYFWEahQvdWSFCcU7p2NUK\n" +
                "cq2zNA6ixO2+fQQhmbrYR+TFxYmhLjCGUNt14E/XaIL1VxPQOA5KbiRPpa8BsUNl\n" +
                "Nik9ASPWyn0ZA0rjJ1ZV7nJarXVbuZDEcUDuDm3cA5tup7juB8fTz2BDcg3Ka+Oc\n" +
                "PEz0GgZfq9K40di3r9IHLBhNPHieFVIj9j/JyMnTvVOceM3J/Rb0MCWJVbXNBKpR\n" +
                "MDibCQh+7fbqyQEM/zIpmk0TgBpTZZqMP0gxYdWImT1IFiEE8tFQpP6Ykl1R6RU5\n" +
                "aE+tYtwDj7tOtggAhgAqvOB142L2SkS3ZIdwuhAtWLPHCtEwBOqGtP8Z204rqAmb\n" +
                "nJymzo77+OT+SScnDTrwzOUJnCi0qPUxfuxhvHxnBxBIjaoMcF++iKsqF1vf6WuX\n" +
                "OjbJ1N8I08pB2niht5MxIZ9rMGDeASj79X7I9Jjzsd30OVGfTZyy3VyYPxcJ6n/s\n" +
                "ZocNmaTv0/F8K3TirSH6JDXdY5zirRi99GJ3R+AL6OzxrChuvLFSEtIRJrW5XVfg\n" +
                "3whc0XD+5J9RsHoL33ub9ZhQHFKsjrf0nGYbEFwMhSdysfTYYMbwKi0CcQeQtPP0\n" +
                "Y87zSryajDMFXQS0exdvhN4AXDlPlB3Rrkj7CQ==\n" +
                "=yTKS\n" +
                "-----END PGP ARMORED FILE-----\n";

        PGPPublicKeyRing keyRing = PGPainless.readKeyRing().publicKeyRing(key);
        PGPPublicKeyRing validated = KeyRingValidator.validate(keyRing, PGPainless.getPolicy());

        Iterator<PGPPublicKey> keys = validated.getPublicKeys();
        assertFalse(keys.next().hasRevocation());
        assertTrue(keys.next().hasRevocation());
    }

    @Test
    public void badSignatureTest() throws IOException {
        String key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
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
                "NEJd3XZRzaXZE2aAMcLA9gQYAQoAIBYhBNGmbhojsYLJmA94jPv8yCoBXnMwBQJd\n" +
                "pZzyAhsMAAoJEPv8yCoBXnMw6f8L/26C34dkjBffTzMj5Bdzm8MtF67OYneJ4TQM\n" +
                "w7+41IL4rVcSKhIhk/3Ud5knaRtP2ef1+5F66h9/RPQOJ5+tvBwhBAcUWSupKnUr\n" +
                "dVaZQanYmtSxcVV2PL9+QEiNN3tzluhaWO//rACxJ+K/ZXQlIzwQVTpNhfGzAaMV\n" +
                "V9zpf3u0k14itcv6alKY8+rLZvO1wIIeRZLmU0tZDD5HtWDvUV7rIFI1WuoLb+KZ\n" +
                "gbYn3OWjCPHVdTrdZ2CqnZbG3SXw6awH9bzRLV9EXkbhIMez0deCVdeo+wFFklh8\n" +
                "/5VK2b0vk/+wqMJxfpa1lHvJLobzOP9fvrswsr92MA2+k901WeISR7qEzcI0Fdg8\n" +
                "AyFAExaEK6VyjP7SXGLwvfisw34OxuZr3qmx1Sufu4toH3XrB7QJN8XyqqbsGxUC\n" +
                "BqWif9RSK4xjzRTe56iPeiSJJOIciMP9i2ldI+KgLycyeDvGoBj0HCLO3gVaBe4u\n" +
                "bVrj5KjhX2PVNEJd3XZRzaXZE2Z/MQ==\n" +
                "=6+l9\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(key);
        PGPPublicKeyRing validated = KeyRingValidator.validate(publicKeys, PGPainless.getPolicy());
        // CHECKSTYLE:OFF
        System.out.println(ArmorUtils.toAsciiArmoredString(validated));
        // CHECKSTYLE:ON
    }

    @Test
    public void unboundSubkey() throws IOException {
        String key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
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
                "NEJd3XZRzaXZE2aAMc7ATQRgSLpPAQgAx2jWKrOk6fGy2/KJGTs6vAN8c+fg+PgH\n" +
                "6xDkasqmGllG0xPVOTML+Ge3i025IezFp1BNApPLWVksFRnbTF/Aiwbpeax7mub0\n" +
                "PdFo4LeNxfUZhl/83+aZKYvT/j9AB7rjILhu+wqZmLY9UAkdvIO0SfEUIFf0mL5c\n" +
                "9UJm47IOpY0EPc8l7B5DkXpkA63BKGyMPle6XZV3r/VIltnMnQezY1TErjeEnFrE\n" +
                "KYxqMgDhPIEaBSK8tqf3POwY2mP42K8+yke/St9+FvLIAKOj2KpVp/0pxcNBBoHA\n" +
                "9oo0W4CQP6S0hQkFZy9iZ1/NIpU+YLy8miBpdTMYm4CZLz5mrT2mpwARAQAB\n" +
                "=T4QR\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";

        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(key);
        PGPPublicKey unbound = CollectionUtils.iteratorToList(publicKeys.getPublicKeys()).get(2);
        assertNotNull(unbound);

        Date validationDate = DateUtil.parseUTCDate("2019-10-15 10:18:26 UTC");
        KeyRingInfo info = new KeyRingInfo(publicKeys, validationDate);
        for (PGPPublicKey publicKey : publicKeys) {
            if (publicKey != unbound) {
                assertTrue(info.isKeyValidlyBound(publicKey.getKeyID()));
            } else {
                assertFalse(info.isKeyValidlyBound(publicKey.getKeyID()));
            }
        }
    }

    @Test
    public void expired() throws IOException {
        String key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
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
                "bGU+wsFcBBMBCgCQBYJgSLnzBYkCH0c9BQsJCAcCCRD7/MgqAV5zMEcUAAAAAAAe\n" +
                "ACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmcwVhGjJD1hkSHawAIfkCGs\n" +
                "HrkFeok37qxAtN/xGj08tAYVCgkICwIEFgIDAQIXgAIbAwIeARYhBNGmbhojsYLJ\n" +
                "mA94jPv8yCoBXnMwAABJmgwAh3SdjziuXu5K4slejN57yezIZBG92CCEfqdoFOE/\n" +
                "LShjMkZbRZEjOADmwTUevAVNRzBtU6SesOE3lL+sHsdmwcQACEbQXvT6AaDQnkyT\n" +
                "N/Kse4reDLA+Cwdvy+dKdIF5g1IKzLc5gSSHHlGi0dc4kTQYXicXl4rw6y4fgfx8\n" +
                "6wWf9ujUexjI35X1A3+yGVkB12lDC4XxcIuQjd2PnxsrRIk8ty32qtv+4Ww3YrvA\n" +
                "wsY7ft9YkMRs7kJ7joVuCWbzje/mpYOSc7t3TCx0VgkRtcXewyGQ22977Vkdk+gi\n" +
                "zmw/f/fV+s1fPzhLYonlmiWwU7COF9dDkuEh2NOkAcuZxVZ/QjMZ449M8kBgCLcD\n" +
                "JGrEzIseP9vW8EHRNGxOZx/0Bo0HPMSlUesOugsoIVXBop/ixtd1eD5ijQt6HhvW\n" +
                "CgASMtfpA4DT9boeGRYXH4vySDqoHPVkKDKYqDHZ526Z98M1a/76njOLVgioIOL/\n" +
                "gND3vo4iOAfwfoQIvi8b/B0fzsDNBF2lnPIBDADWML9cbGMrp12CtF9b2P6z9TTT\n" +
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
                "=LxAY\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";

        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(key);
        PGPPublicKeyRing validated = KeyRingValidator.validate(publicKeys, PGPainless.getPolicy());
    }

    @Test
    public void testKeyWithUserAttributes() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Alice <alice@pgpainless.org>", null);
        PGPPublicKeyRing publicKeys = PGPainless.extractCertificate(secretKeys);
        PGPPublicKey publicKey = secretKeys.getPublicKey();
        PGPSecretKey secretKey = secretKeys.getSecretKey();
        PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(secretKey, SecretKeyRingProtector.unprotectedKeys());

        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                ImplementationFactory.getInstance().getPGPContentSignerBuilder(publicKey.getAlgorithm(), HashAlgorithm.SHA512.getAlgorithmId())
        );

        signatureGenerator.init(SignatureType.CASUAL_CERTIFICATION.getCode(), privateKey);
        PGPUserAttributeSubpacketVectorGenerator userAttrGen = new PGPUserAttributeSubpacketVectorGenerator();
        byte[] image = new byte[100];
        new Random().nextBytes(image);
        userAttrGen.setImageAttribute(ImageAttribute.JPEG, image);
        PGPUserAttributeSubpacketVector userAttr = userAttrGen.generate();

        PGPSignature certification = signatureGenerator.generateCertification(userAttr, publicKey);
        publicKey = PGPPublicKey.addCertification(publicKey, userAttr, certification);
        publicKeys = PGPPublicKeyRing.insertPublicKey(publicKeys, publicKey);
        secretKeys = PGPSecretKeyRing.replacePublicKeys(secretKeys, publicKeys);

        secretKeys = KeyRingValidator.validate(secretKeys, PGPainless.getPolicy());
        assertTrue(secretKeys.getPublicKey().getUserAttributes().hasNext());
    }
}
