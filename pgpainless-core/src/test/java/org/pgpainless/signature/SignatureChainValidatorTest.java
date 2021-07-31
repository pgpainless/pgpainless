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
package org.pgpainless.signature;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.policy.Policy;

public class SignatureChainValidatorTest {

    /**
     * Primary Key signs and is hard revoked with reason: unknown.
     *
     * @see <a href="https://tests.sequoia-pgp.org/#Key_revocation_test__primary_key_signs_and_is_revoked__revoked__unknown">Sequoia Test Suite</a>
     */
    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void testPrimaryKeySignsAndIsHardRevokedUnknown(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

        String key = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "xsBNBFpJegABCAC1ePFquP0135m8DYhcybhv7l+ecojitFOd/jRM7hCczIqKgalD\n" +
                "1Ro1gNr3VmH6FjRIKIvGT+sOzCKne1v3KyAAPoxtwxjkATTKdOGo15I6v5ZjmO1d\n" +
                "rLQOLSt1TF7XbQSt+ns6PUZWJL907DvECUU5b9FkNUqfQ14QqY+gi7MOyAQez3b7\n" +
                "Pg5Cyz/kVWQ6TSMW/myDEDEertQ4rDBsptEDFHCC2+iF4hO2LqfiCriu5qyLcKCQ\n" +
                "pd6dEuwJQ/jjT0D9A9Fwf+i04x6ZPKSU9oNAWqn8OSAq3/0B/hu9V+0U0iHPnJxe\n" +
                "quykvJk7maxhiGhxBWYXTvDJmoon0NOles7LABEBAAHCwJMEIAEKACYFglwqrYAf\n" +
                "HchVbmtub3duIHJldm9jYXRpb24gcmVhc29uIDIwMAAhCRBoT61i3AOPuxYhBPLR\n" +
                "UKT+mJJdUekVOWhPrWLcA4+7yUoH/1KmYWve5h9Tsl1dAguIwVhqNw5fQjxYQCy2\n" +
                "kq+1XBBjKSalNpoFIgV0fJWo+x8i3neNH0pnWRPR9lddiW3C/TjsjGp69QvYaZnM\n" +
                "NXGymkvb6JMFGtTBwpM6R8iH0UqQHWK984nEcD4ZTU2zWY5Q3zr/ahKDoMKooqbc\n" +
                "tBlMumQ3KhSmDrJlU7xxn0K3A5bZoHd/ZlIxk7FX7yoSBUffy6gRdT0IFk9X93Vn\n" +
                "GuUpo+vTjEBO3PQuKOMOT0qJxqZHCUN0LWHDdH3IwmfrlRSRWq63pbO6pyHyEehS\n" +
                "5LQ7NbP994BNxT9yYQ3REvk/ngJk4aK5xRHXdPL529Dio4XWZ4rCwHwEHwEKAA8F\n" +
                "gl4L4QACFQoCmwMCHgEAIQkQaE+tYtwDj7sWIQTy0VCk/piSXVHpFTloT61i3AOP\n" +
                "u8ffB/9Q60dg60qhA2rPnd/1dCL2B+c8RWnq44PpijE3gA1RQvcRQE5jNzMSo/Mn\n" +
                "G0mSL5wHeTsjSd/DRI3nHP06rs6Qub11NoKhNuya3maz9gyzeZMc/jNib83/BzFC\n" +
                "rxsSQm+9WHurxXeWXOPMLZs3xS/jG0EDtCJ2Fm4UF19fcIydwN/ssF4NGpfCY82+\n" +
                "wTSx4joI3cRKObCFJaaBgG5nl+eFr7cfjEIuqCJCaQsXiqBe7d6V3KqN18t+CgSa\n" +
                "ybMZXcysQ/USxEkLhIB2pOZwcz4E3TTFgxRAxcr4cs4Bd2PRz3Z5FKTzo0ma/Ft0\n" +
                "UfFJR+fCcs55+n6kC9K0y/E7BY2hwsB8BB8BCgAPBYJaSXoAAhUKApsDAh4BACEJ\n" +
                "EGhPrWLcA4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwDj7uqDQf7BqTD6GNTwXPOt/0k\n" +
                "HQPYmbdItX+pWP+o3jaB6VTHDXcn27bttA5M82EXZfae4+bC1dMB+1uLal4ciVgO\n" +
                "9ImJC9Nws5fc3JH4R5uuSvpjzjudkJsGu3cAKE3hwiT93Mi6t6ENpLCDSxqxzAmf\n" +
                "oOQbVJYWY7gP7Z4Cj0IAP29aprEc0JWoMjHKpKgYF6u0sWgHWBuEXk/6o6GYb2HZ\n" +
                "YK4ycpY2WXKgVhy7/iQDYO1FOfcWQXHVGLn8OzILjobKohNenTT20ZhAASi3LUDS\n" +
                "DMTQfxSSVt0nhzWuXJJ4R8PzUVeRJ0A0oMyjZVHivHC6GwMsiQuSUTx8e/GnOByO\n" +
                "qfGne80SanVsaWV0QGV4YW1wbGUub3JnwsBzBBMBCgAGBYJaSXoAACEJEGhPrWLc\n" +
                "A4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwDj7tDfQf+PnxsIFu/0juKBUjjtAYfRzkr\n" +
                "rYtMepPjtaTvGfo1SzUkX/6F/GjdSeVg5Iq6YcBrj8c+cB3EoZpHnScTgWQHwceW\n" +
                "QLd9HhbgTrUNvW1eg2CVzN0RBuYMtWu9JM4pH7ssJW1NmN+/N9B67qb2y+JfBwH/\n" +
                "la508NzCrl3xWTxjT5wNy+FGkNZg23s/0qlO2uxCjc+mRAuAlp5EmTOVWOIBbM0x\n" +
                "ttjBOx39ZmWWQKJZ0nrFjK1jppHqazwWWNX7RHkK81tlbSUtOPoTIJDz38NaiyMc\n" +
                "ZH3p9okN3DU4XtF+oE18M+Z/E0xUQmumbkajFzcUjmd7enozP5BnGESzdNS5Xc7A\n" +
                "TQRaSsuAAQgAykb8tqlWXtqHGGkBqAq3EnpmvBqrKvqejjtZKAXqEszJ9NlibCGU\n" +
                "uLwnNOVOR/hcOUlOGH+cyMcApBWJB+7d/83K1eCCdv88nDFVav7hKLKlEBbZJNHg\n" +
                "HpJ313pletzCR4x3STEISrEtO71l2HBdrKSYXaxGgILxYwcSi3i2EjzxRDy+0zyy\n" +
                "8s7d+OD5ShFYexgSrKH3Xx1cxQAJzGGJVx75HHU9GVh3xHwJ7nDm26KzHegG2XPI\n" +
                "BXJ2z8vmsSVTWyj0AjT4kVVapN0f84AKKjyQ7fguCzXGHFV9jmxDx+YH+9HhjIrH\n" +
                "SzbDx6+4wyRsxj7Su+hu/bogJ28nnbTzQwARAQABwsGsBBgBCgAJBYJeC+EAApsC\n" +
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
                "=MhJL\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigPredatesPrimaryKey = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJYaEaAACEJEGhPrWLcA4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwD\n" +
                "j7ttqgf9Gp4T5Q19cNL9Eyz1nlw11HDHT1wxfGHU5li76y7oo4Jqim15sEPDJWmc\n" +
                "IpYVrczpCI95aCuaE6yfzpjZlXMzftwex3DjM98vyZH4W9teKcOnpAVjn3dLoQJA\n" +
                "i4fiq3VaLgl+1OYOwu3DmwGKJZubHM3oPia9pbuyvL5Scvx+QCG0AVnssnt2QswG\n" +
                "uU6J35QgBdjG2iC043sUoyxTSk929iamdQnOGchjcaATb4E4+HvtkRy4IirKxiKK\n" +
                "c535BHJRLgWQzUcDDZ5kHf3SPLTNsigFFEwUyf5voFcn/DSMWSzPaVecaafTVJW2\n" +
                "u8G1R5mjuxDRup8p//X1BSk1FpSmvw==\n" +
                "=3/dv\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigSubkeyNotBound = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJa564AACEJEGhPrWLcA4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwD\n" +
                "j7ufRgf/QOsaJZgQaQ5daQrfBItOEcW+5acgY1TCwMVmc/nzBqC32TOvMaM3dypf\n" +
                "wJbqzxHQIes+ivKDF872VWlMA2BErifpdsogbS0pdik/qU+AjMhr188xKpZKG/IY\n" +
                "6BtuUPeSpsimx3UeEN3kt79fMtewBo0EXo3ujCyPpIF/9Vpd7L9jlJSvRBuM0/aR\n" +
                "gbRsclEw4JZ98B3t7F3rLmx+F57Zre0ctzT4tHE6IaCYpEClr6Tepj/UxExYOt2l\n" +
                "hKgVN8Wsuug7XYdOFmxqrV967m3CTnF8AspmxwgKK6NXjVLplfqij7Rp2URPWrWn\n" +
                "Pp3CQRGUWJdMeMY9P1MpFq6XiXtftw==\n" +
                "=Ld1q\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigPrimaryKeyRevoked = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJdP4iAACEJEGhPrWLcA4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwD\n" +
                "j7sYXQf8CZw6Kx4oyI8ZJ2c9RjVZmUFEirAoXH7oYA+Ye+wSAY9OtqE/x2SOYaC6\n" +
                "QHiB93/wkvpqCVkLy2lenzpD7WXLbuFZ+/5jXp1o+sVHXfLSWo6pfIhOjj9FSr8x\n" +
                "qqlqUfKwkbA6WYgju+qKC35SYdSptix7unaFkO41UdsM8wGQh880HSRMBMFPzg07\n" +
                "3hMNYXoEJjFlIkxJSMu2WL7N0Q/4xE2iJftsQjUYAtJ/C/YK2I6dhW+CZremnv5R\n" +
                "/8W+oH5Q63lYU8YL4wYnJQvkHjKs/kjLpoPmqL8kdHjndSpU+KOYr5w61XuEp2hp\n" +
                "r8trtljVaVIQX2rYawSlqKkWXt0yag==\n" +
                "=xVd8\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigPrimaryKeyRevalidated = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJe/cFVACEJEGhPrWLcA4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwD\n" +
                "j7vmhQf/UB456IXc8ub8HTExab1d5KqOGSUWpwIznTu8Wk8YuzWKEE8ZeZvPmv8K\n" +
                "iJfBoOx59YrlOfpLAKcTR9Ql+IFbWsIkqPxX7U1SGldhfQm7iaK5Dn6+mmQFOz/s\n" +
                "ZCIavWJ7opsp11JmQAt4FFojv789YswaS7VI1zjDj7EeRiATtzna/GqCYgeCM0cc\n" +
                "sIe/1j1H2oh9YvYIpPMSGDJPo7T1Ji4Ie3iEQEYNYPuw1Hb7gWYncHXZGJq1nDf/\n" +
                "WAoI9gSFagpsPW0k9cfEAOVNLNYSyi0CSnQWSjq8THbHKiLPFwsP3hvT2oHycWbK\n" +
                "u5SfXaTsbMeVQJNdjCNsHq2bOXPGLw==\n" +
                "=2BW4\n" +
                "-----END PGP ARMORED FILE-----\n";

        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(key);
        PGPSignature predatesPrimaryKey = SignatureUtils.readSignatures(sigPredatesPrimaryKey).get(0);
        PGPSignature unboundSubkey = SignatureUtils.readSignatures(sigSubkeyNotBound).get(0);
        PGPSignature primaryKeyRevoked = SignatureUtils.readSignatures(sigPrimaryKeyRevoked).get(0);
        PGPSignature primaryKeyRevalidated = SignatureUtils.readSignatures(sigPrimaryKeyRevalidated).get(0);

        Policy policy = PGPainless.getPolicy();
        Date validationDate = new Date();
        String data = "Hello, World";

        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                predatesPrimaryKey, getSignedData(data), publicKeys, policy, validationDate),
                "Signature predates primary key");
        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                unboundSubkey, getSignedData(data), publicKeys, policy, validationDate),
                "Primary key hard revoked");
        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                primaryKeyRevoked, getSignedData(data), publicKeys, policy, validationDate),
                "Primary key hard revoked");
        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                primaryKeyRevalidated, getSignedData(data), publicKeys, policy, validationDate),
                "Primary key hard revoked");
    }

    /**
     * Subkey signs, primary key is hard revoked with reason: unknown.
     * @see <a href="https://tests.sequoia-pgp.org/#Key_revocation_test__subkey_signs__primary_key_is_revoked__revoked__unknown">Sequoia Test Suite</a>
     */
    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void testSubkeySignsPrimaryKeyIsHardRevokedUnknown(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

        String key = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "xsBNBFpJegABCAC1ePFquP0135m8DYhcybhv7l+ecojitFOd/jRM7hCczIqKgalD\n" +
                "1Ro1gNr3VmH6FjRIKIvGT+sOzCKne1v3KyAAPoxtwxjkATTKdOGo15I6v5ZjmO1d\n" +
                "rLQOLSt1TF7XbQSt+ns6PUZWJL907DvECUU5b9FkNUqfQ14QqY+gi7MOyAQez3b7\n" +
                "Pg5Cyz/kVWQ6TSMW/myDEDEertQ4rDBsptEDFHCC2+iF4hO2LqfiCriu5qyLcKCQ\n" +
                "pd6dEuwJQ/jjT0D9A9Fwf+i04x6ZPKSU9oNAWqn8OSAq3/0B/hu9V+0U0iHPnJxe\n" +
                "quykvJk7maxhiGhxBWYXTvDJmoon0NOles7LABEBAAHCwJMEIAEKACYFglwqrYAf\n" +
                "HchVbmtub3duIHJldm9jYXRpb24gcmVhc29uIDIwMAAhCRBoT61i3AOPuxYhBPLR\n" +
                "UKT+mJJdUekVOWhPrWLcA4+7yUoH/1KmYWve5h9Tsl1dAguIwVhqNw5fQjxYQCy2\n" +
                "kq+1XBBjKSalNpoFIgV0fJWo+x8i3neNH0pnWRPR9lddiW3C/TjsjGp69QvYaZnM\n" +
                "NXGymkvb6JMFGtTBwpM6R8iH0UqQHWK984nEcD4ZTU2zWY5Q3zr/ahKDoMKooqbc\n" +
                "tBlMumQ3KhSmDrJlU7xxn0K3A5bZoHd/ZlIxk7FX7yoSBUffy6gRdT0IFk9X93Vn\n" +
                "GuUpo+vTjEBO3PQuKOMOT0qJxqZHCUN0LWHDdH3IwmfrlRSRWq63pbO6pyHyEehS\n" +
                "5LQ7NbP994BNxT9yYQ3REvk/ngJk4aK5xRHXdPL529Dio4XWZ4rCwHwEHwEKAA8F\n" +
                "gl4L4QACFQoCmwMCHgEAIQkQaE+tYtwDj7sWIQTy0VCk/piSXVHpFTloT61i3AOP\n" +
                "u8ffB/9Q60dg60qhA2rPnd/1dCL2B+c8RWnq44PpijE3gA1RQvcRQE5jNzMSo/Mn\n" +
                "G0mSL5wHeTsjSd/DRI3nHP06rs6Qub11NoKhNuya3maz9gyzeZMc/jNib83/BzFC\n" +
                "rxsSQm+9WHurxXeWXOPMLZs3xS/jG0EDtCJ2Fm4UF19fcIydwN/ssF4NGpfCY82+\n" +
                "wTSx4joI3cRKObCFJaaBgG5nl+eFr7cfjEIuqCJCaQsXiqBe7d6V3KqN18t+CgSa\n" +
                "ybMZXcysQ/USxEkLhIB2pOZwcz4E3TTFgxRAxcr4cs4Bd2PRz3Z5FKTzo0ma/Ft0\n" +
                "UfFJR+fCcs55+n6kC9K0y/E7BY2hwsB8BB8BCgAPBYJaSXoAAhUKApsDAh4BACEJ\n" +
                "EGhPrWLcA4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwDj7uqDQf7BqTD6GNTwXPOt/0k\n" +
                "HQPYmbdItX+pWP+o3jaB6VTHDXcn27bttA5M82EXZfae4+bC1dMB+1uLal4ciVgO\n" +
                "9ImJC9Nws5fc3JH4R5uuSvpjzjudkJsGu3cAKE3hwiT93Mi6t6ENpLCDSxqxzAmf\n" +
                "oOQbVJYWY7gP7Z4Cj0IAP29aprEc0JWoMjHKpKgYF6u0sWgHWBuEXk/6o6GYb2HZ\n" +
                "YK4ycpY2WXKgVhy7/iQDYO1FOfcWQXHVGLn8OzILjobKohNenTT20ZhAASi3LUDS\n" +
                "DMTQfxSSVt0nhzWuXJJ4R8PzUVeRJ0A0oMyjZVHivHC6GwMsiQuSUTx8e/GnOByO\n" +
                "qfGne80SanVsaWV0QGV4YW1wbGUub3JnwsBzBBMBCgAGBYJaSXoAACEJEGhPrWLc\n" +
                "A4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwDj7tDfQf+PnxsIFu/0juKBUjjtAYfRzkr\n" +
                "rYtMepPjtaTvGfo1SzUkX/6F/GjdSeVg5Iq6YcBrj8c+cB3EoZpHnScTgWQHwceW\n" +
                "QLd9HhbgTrUNvW1eg2CVzN0RBuYMtWu9JM4pH7ssJW1NmN+/N9B67qb2y+JfBwH/\n" +
                "la508NzCrl3xWTxjT5wNy+FGkNZg23s/0qlO2uxCjc+mRAuAlp5EmTOVWOIBbM0x\n" +
                "ttjBOx39ZmWWQKJZ0nrFjK1jppHqazwWWNX7RHkK81tlbSUtOPoTIJDz38NaiyMc\n" +
                "ZH3p9okN3DU4XtF+oE18M+Z/E0xUQmumbkajFzcUjmd7enozP5BnGESzdNS5Xc7A\n" +
                "TQRaSsuAAQgAykb8tqlWXtqHGGkBqAq3EnpmvBqrKvqejjtZKAXqEszJ9NlibCGU\n" +
                "uLwnNOVOR/hcOUlOGH+cyMcApBWJB+7d/83K1eCCdv88nDFVav7hKLKlEBbZJNHg\n" +
                "HpJ313pletzCR4x3STEISrEtO71l2HBdrKSYXaxGgILxYwcSi3i2EjzxRDy+0zyy\n" +
                "8s7d+OD5ShFYexgSrKH3Xx1cxQAJzGGJVx75HHU9GVh3xHwJ7nDm26KzHegG2XPI\n" +
                "BXJ2z8vmsSVTWyj0AjT4kVVapN0f84AKKjyQ7fguCzXGHFV9jmxDx+YH+9HhjIrH\n" +
                "SzbDx6+4wyRsxj7Su+hu/bogJ28nnbTzQwARAQABwsGsBBgBCgAJBYJeC+EAApsC\n" +
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
                "=MhJL\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigPredatesPrimaryKey = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJYaEaAACEJEEpyNKOhITplFiEEUXksDkji/alOk7kRSnI0o6Eh\n" +
                "OmVtqgf/YSG+b8lY01/4oCrHoNMECDDbpI5+8WkeT0CcdlEd5TGj3AHesT6H6XmL\n" +
                "ZxaHHOwtkuDh0bIAiYGl36e4ult5XZQhFIwUXGde6myLE+fpCGsBJwNu+TDIrbg3\n" +
                "PGqnVZNlcU+2sP5JhJfAn8VtLENuHkbIC3+kH8xBIrkPTc0rbNBgyzX5eFO20U0D\n" +
                "bHCCjfjVDpZ8l7N2NlsRYvU0kTzN5GvwbS1HnMOovF9ZKkEpzxxw6IRJIapaE2L9\n" +
                "adMKIRAqrIIjfj6Z9nETd1nZE79t1zSw1trfArPaJQr46krgh1ocLQoD/c+PhB9l\n" +
                "sRxQBnWERgQaDJByq0kwKSnwWAsyxw==\n" +
                "=SDmD\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigSigningKeyUnbound = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJa564AACEJEEpyNKOhITplFiEEUXksDkji/alOk7kRSnI0o6Eh\n" +
                "OmWfRgf9ECjIviU1pN0GiMZGci3Vce2b42LIqH0JZApOeRDpcyXgxi3/CmdaewpT\n" +
                "w9l18gsXhioRg4xUzMFrYSgyYZ9VajFggMjbeX5dSV3rsOSJSiEEyDbeGi0TcA/Y\n" +
                "GUifX4EfKx5X5nI/wevnYjmruDp9SqaPLHIZK1soOoPzueZ8wKyJ9A4vVG4bvxVX\n" +
                "FnwBf6mRE/0Z8IoHlRJdq0fSzW4RgX8KAtK8SfyGOnk7LDaevVuL6iE5v0Gsu0oh\n" +
                "cHlI6Llm97EVxP93KZ1J7TQIi/a6PUJb5XCIw0K/iyuNuAzETgm8LVJyn6UwL4ym\n" +
                "KcNieOK8Qcoivq0kCYuv/0Tbk13jVQ==\n" +
                "=5hOz\n" +
                "-----END PGP ARMORED FILE-----";
        String sigSubkeyRevoked = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJdP4iAACEJEEpyNKOhITplFiEEUXksDkji/alOk7kRSnI0o6Eh\n" +
                "OmUYXQf/dGNZay40bZEpcnxYl+Kq+gRQESeDhg/xOfGfSCLQncMH+UYPaUKANC2g\n" +
                "CfMNN1wd8ZWrvgyTVo3TVfK1P1RYa9nrvKoKN3bjsFcY6V7VciPW58xVNsuxsEEC\n" +
                "GEH96TQy+FsP680tRnzQ3Dbw/JT6o6Xi+HLf4JVFceapBgyth61E5gN5w3azxVFr\n" +
                "GfwIfHvepOjCIq9tRZsRFEBp3XVZ/AF+zQMG5nfIVSm1kVtZjb7KXc3Bj48DVrmb\n" +
                "XLxPJz7PLY0cgOsXXxROIdtFT+mbVQg2j247hxnhItwtLeQrafb5T8ibeihRlkhK\n" +
                "1tfKv31EP8tAVqgTjw+qD32bH9h77w==\n" +
                "=MOaJ\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigSubkeyRevalidated = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJe/cFVACEJEEpyNKOhITplFiEEUXksDkji/alOk7kRSnI0o6Eh\n" +
                "OmXmhQf+LjM2vmdKYnxfVy40Vcdoy2Jov/ZD2RSMFff+fIoCXmWfEetila7v5xHj\n" +
                "ZXq6aevTEN1vgW3T6Q1OjFhnGpMl9wvya9mszfn5BBKukFtLkHeay0PtYuUcrfJC\n" +
                "UIQCx9PFZzgRJFyGsCqrXBc1VIe2DV3d8dq74unTeCEmWdvAZKdjoUYzRohMtcZ+\n" +
                "0QctCCJE1kRFJuH/TIdxxwKPtBZfOolSlpS0Z5xxa2sILqUvQ2Dq3hBctUM4g6hB\n" +
                "Y8uafI8qIMwWl4DQDzPpQ917d6J+GCdN0Aib6ZOsvmgR5wrBOFiDpRJ/W9W6+rgs\n" +
                "I5V/t2y6h6gaHbanggc0cMOaMTtEKQ==\n" +
                "=lkHs\n" +
                "-----END PGP ARMORED FILE-----\n";

        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(key);
        PGPSignature predatesPrimaryKey = SignatureUtils.readSignatures(sigPredatesPrimaryKey).get(0);
        PGPSignature unboundSubkey = SignatureUtils.readSignatures(sigSigningKeyUnbound).get(0);
        PGPSignature revokedSubkey = SignatureUtils.readSignatures(sigSubkeyRevoked).get(0);
        PGPSignature revalidatedSubkey = SignatureUtils.readSignatures(sigSubkeyRevalidated).get(0);

        Policy policy = PGPainless.getPolicy();
        Date validationDate = new Date();
        String data = "Hello, World";

        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                predatesPrimaryKey, getSignedData(data), publicKeys, policy, validationDate),
                "Signature predates primary key");
        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                unboundSubkey, getSignedData(data), publicKeys, policy, validationDate),
                "Signing key unbound + hard revocation");
        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                revokedSubkey, getSignedData(data), publicKeys, policy, validationDate),
                "Primary key is hard revoked");
        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                revalidatedSubkey, getSignedData(data), publicKeys, policy, validationDate),
                "Primary key is hard revoked");
    }

    /**
     * Subkey signs and is hard revoked with reason: unknown.
     *
     * @see <a href="https://tests.sequoia-pgp.org/#Key_revocation_test__subkey_signs__subkey_is_revoked__revoked__unknown">Sequoia Test Suite</a>
     */
    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void testSubkeySignsAndIsHardRevokedUnknown(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

        String keyWithHardRev = "-----BEGIN PGP ARMORED FILE-----\n" +
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
        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(keyWithHardRev);
        String sigPredatesPrimaryKey = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJYaEaAACEJEEpyNKOhITplFiEEUXksDkji/alOk7kRSnI0o6Eh\n" +
                "OmVtqgf/YSG+b8lY01/4oCrHoNMECDDbpI5+8WkeT0CcdlEd5TGj3AHesT6H6XmL\n" +
                "ZxaHHOwtkuDh0bIAiYGl36e4ult5XZQhFIwUXGde6myLE+fpCGsBJwNu+TDIrbg3\n" +
                "PGqnVZNlcU+2sP5JhJfAn8VtLENuHkbIC3+kH8xBIrkPTc0rbNBgyzX5eFO20U0D\n" +
                "bHCCjfjVDpZ8l7N2NlsRYvU0kTzN5GvwbS1HnMOovF9ZKkEpzxxw6IRJIapaE2L9\n" +
                "adMKIRAqrIIjfj6Z9nETd1nZE79t1zSw1trfArPaJQr46krgh1ocLQoD/c+PhB9l\n" +
                "sRxQBnWERgQaDJByq0kwKSnwWAsyxw==\n" +
                "=SDmD\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigUnboundBeforeHardRevocation = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJa564AACEJEEpyNKOhITplFiEEUXksDkji/alOk7kRSnI0o6Eh\n" +
                "OmWfRgf9ECjIviU1pN0GiMZGci3Vce2b42LIqH0JZApOeRDpcyXgxi3/CmdaewpT\n" +
                "w9l18gsXhioRg4xUzMFrYSgyYZ9VajFggMjbeX5dSV3rsOSJSiEEyDbeGi0TcA/Y\n" +
                "GUifX4EfKx5X5nI/wevnYjmruDp9SqaPLHIZK1soOoPzueZ8wKyJ9A4vVG4bvxVX\n" +
                "FnwBf6mRE/0Z8IoHlRJdq0fSzW4RgX8KAtK8SfyGOnk7LDaevVuL6iE5v0Gsu0oh\n" +
                "cHlI6Llm97EVxP93KZ1J7TQIi/a6PUJb5XCIw0K/iyuNuAzETgm8LVJyn6UwL4ym\n" +
                "KcNieOK8Qcoivq0kCYuv/0Tbk13jVQ==\n" +
                "=5hOz\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigAfterHardRevocation = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJdP4iAACEJEEpyNKOhITplFiEEUXksDkji/alOk7kRSnI0o6Eh\n" +
                "OmUYXQf/dGNZay40bZEpcnxYl+Kq+gRQESeDhg/xOfGfSCLQncMH+UYPaUKANC2g\n" +
                "CfMNN1wd8ZWrvgyTVo3TVfK1P1RYa9nrvKoKN3bjsFcY6V7VciPW58xVNsuxsEEC\n" +
                "GEH96TQy+FsP680tRnzQ3Dbw/JT6o6Xi+HLf4JVFceapBgyth61E5gN5w3azxVFr\n" +
                "GfwIfHvepOjCIq9tRZsRFEBp3XVZ/AF+zQMG5nfIVSm1kVtZjb7KXc3Bj48DVrmb\n" +
                "XLxPJz7PLY0cgOsXXxROIdtFT+mbVQg2j247hxnhItwtLeQrafb5T8ibeihRlkhK\n" +
                "1tfKv31EP8tAVqgTjw+qD32bH9h77w==\n" +
                "=MOaJ\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigAfterRevalidation = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJe/cFVACEJEEpyNKOhITplFiEEUXksDkji/alOk7kRSnI0o6Eh\n" +
                "OmXmhQf+LjM2vmdKYnxfVy40Vcdoy2Jov/ZD2RSMFff+fIoCXmWfEetila7v5xHj\n" +
                "ZXq6aevTEN1vgW3T6Q1OjFhnGpMl9wvya9mszfn5BBKukFtLkHeay0PtYuUcrfJC\n" +
                "UIQCx9PFZzgRJFyGsCqrXBc1VIe2DV3d8dq74unTeCEmWdvAZKdjoUYzRohMtcZ+\n" +
                "0QctCCJE1kRFJuH/TIdxxwKPtBZfOolSlpS0Z5xxa2sILqUvQ2Dq3hBctUM4g6hB\n" +
                "Y8uafI8qIMwWl4DQDzPpQ917d6J+GCdN0Aib6ZOsvmgR5wrBOFiDpRJ/W9W6+rgs\n" +
                "I5V/t2y6h6gaHbanggc0cMOaMTtEKQ==\n" +
                "=lkHs\n" +
                "-----END PGP ARMORED FILE-----\n";

        PGPSignature predatesPrimaryKey = SignatureUtils.readSignatures(sigPredatesPrimaryKey).get(0);
        PGPSignature unboundKey = SignatureUtils.readSignatures(sigUnboundBeforeHardRevocation).get(0);
        PGPSignature afterHardRevocation = SignatureUtils.readSignatures(sigAfterHardRevocation).get(0);
        PGPSignature afterRevalidation = SignatureUtils.readSignatures(sigAfterRevalidation).get(0);

        Policy policy = PGPainless.getPolicy();
        Date validationDate = new Date();
        String data = "Hello World :)";

        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                predatesPrimaryKey, getSignedData(data), publicKeys, policy, validationDate),
                "Signature predates primary key");
        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                unboundKey, getSignedData(data), publicKeys, policy, validationDate),
                "Signing key unbound + hard revocation");
        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                afterHardRevocation, getSignedData(data), publicKeys, policy, validationDate),
                "Hard revocation invalidates key at all times");
        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                afterRevalidation, getSignedData(data), publicKeys, policy, validationDate),
                "Hard revocation invalidates key at all times");
    }

    /**
     * Primary Key signs and is soft revoked with reason: superseded.
     *
     * @see <a href="https://tests.sequoia-pgp.org/#Key_revocation_test__primary_key_signs_and_is_revoked__revoked__superseded">Sequoia Test Suite</a>
     */
    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void testPrimaryKeySignsAndIsSoftRevokedSuperseded(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

        String keyWithSoftRev = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "xsBNBFpJegABCAC1ePFquP0135m8DYhcybhv7l+ecojitFOd/jRM7hCczIqKgalD\n" +
                "1Ro1gNr3VmH6FjRIKIvGT+sOzCKne1v3KyAAPoxtwxjkATTKdOGo15I6v5ZjmO1d\n" +
                "rLQOLSt1TF7XbQSt+ns6PUZWJL907DvECUU5b9FkNUqfQ14QqY+gi7MOyAQez3b7\n" +
                "Pg5Cyz/kVWQ6TSMW/myDEDEertQ4rDBsptEDFHCC2+iF4hO2LqfiCriu5qyLcKCQ\n" +
                "pd6dEuwJQ/jjT0D9A9Fwf+i04x6ZPKSU9oNAWqn8OSAq3/0B/hu9V+0U0iHPnJxe\n" +
                "quykvJk7maxhiGhxBWYXTvDJmoon0NOles7LABEBAAHCwIcEIAEKABoFglwqrYAT\n" +
                "HQFLZXkgaXMgc3VwZXJzZWRlZAAhCRBoT61i3AOPuxYhBPLRUKT+mJJdUekVOWhP\n" +
                "rWLcA4+76+wH/1NmN/Qma5FTxmSWEcfH2ynKhwejKp8p8O7+y/uq1FlUwRzChzeX\n" +
                "kd9w099uODMasxGaNSJU1mh5N+1oulyHrSyWFRWqDnQUnDx3IiPapK/j85udkJdo\n" +
                "WfdTcxaS2C9Yo4S77cPwkbFLmEQ2Ovs5zjj0Q+mfoZNM+KJcsnOoJ+eeOE2GNA3x\n" +
                "5TWvw0QXBfyW74MZHc0UE82ixcG6g4KbrI6W544EixY5vu3IxVsxiL66zy27A8ha\n" +
                "EDdBWS8kc8UQ2cRveuqZwRsWcrh/2iHHShY/5zBOdQ1PL++ubwkteNSU9SsXjjDM\n" +
                "oWm1RGy7/bagPPtqBnRMQ20vvW+3oBYxyd7CwHwEHwEKAA8Fgl4L4QACFQoCmwMC\n" +
                "HgEAIQkQaE+tYtwDj7sWIQTy0VCk/piSXVHpFTloT61i3AOPu8ffB/9Q60dg60qh\n" +
                "A2rPnd/1dCL2B+c8RWnq44PpijE3gA1RQvcRQE5jNzMSo/MnG0mSL5wHeTsjSd/D\n" +
                "RI3nHP06rs6Qub11NoKhNuya3maz9gyzeZMc/jNib83/BzFCrxsSQm+9WHurxXeW\n" +
                "XOPMLZs3xS/jG0EDtCJ2Fm4UF19fcIydwN/ssF4NGpfCY82+wTSx4joI3cRKObCF\n" +
                "JaaBgG5nl+eFr7cfjEIuqCJCaQsXiqBe7d6V3KqN18t+CgSaybMZXcysQ/USxEkL\n" +
                "hIB2pOZwcz4E3TTFgxRAxcr4cs4Bd2PRz3Z5FKTzo0ma/Ft0UfFJR+fCcs55+n6k\n" +
                "C9K0y/E7BY2hwsB8BB8BCgAPBYJaSXoAAhUKApsDAh4BACEJEGhPrWLcA4+7FiEE\n" +
                "8tFQpP6Ykl1R6RU5aE+tYtwDj7uqDQf7BqTD6GNTwXPOt/0kHQPYmbdItX+pWP+o\n" +
                "3jaB6VTHDXcn27bttA5M82EXZfae4+bC1dMB+1uLal4ciVgO9ImJC9Nws5fc3JH4\n" +
                "R5uuSvpjzjudkJsGu3cAKE3hwiT93Mi6t6ENpLCDSxqxzAmfoOQbVJYWY7gP7Z4C\n" +
                "j0IAP29aprEc0JWoMjHKpKgYF6u0sWgHWBuEXk/6o6GYb2HZYK4ycpY2WXKgVhy7\n" +
                "/iQDYO1FOfcWQXHVGLn8OzILjobKohNenTT20ZhAASi3LUDSDMTQfxSSVt0nhzWu\n" +
                "XJJ4R8PzUVeRJ0A0oMyjZVHivHC6GwMsiQuSUTx8e/GnOByOqfGne80SanVsaWV0\n" +
                "QGV4YW1wbGUub3JnwsBzBBMBCgAGBYJaSXoAACEJEGhPrWLcA4+7FiEE8tFQpP6Y\n" +
                "kl1R6RU5aE+tYtwDj7tDfQf+PnxsIFu/0juKBUjjtAYfRzkrrYtMepPjtaTvGfo1\n" +
                "SzUkX/6F/GjdSeVg5Iq6YcBrj8c+cB3EoZpHnScTgWQHwceWQLd9HhbgTrUNvW1e\n" +
                "g2CVzN0RBuYMtWu9JM4pH7ssJW1NmN+/N9B67qb2y+JfBwH/la508NzCrl3xWTxj\n" +
                "T5wNy+FGkNZg23s/0qlO2uxCjc+mRAuAlp5EmTOVWOIBbM0xttjBOx39ZmWWQKJZ\n" +
                "0nrFjK1jppHqazwWWNX7RHkK81tlbSUtOPoTIJDz38NaiyMcZH3p9okN3DU4XtF+\n" +
                "oE18M+Z/E0xUQmumbkajFzcUjmd7enozP5BnGESzdNS5Xc7ATQRaSsuAAQgAykb8\n" +
                "tqlWXtqHGGkBqAq3EnpmvBqrKvqejjtZKAXqEszJ9NlibCGUuLwnNOVOR/hcOUlO\n" +
                "GH+cyMcApBWJB+7d/83K1eCCdv88nDFVav7hKLKlEBbZJNHgHpJ313pletzCR4x3\n" +
                "STEISrEtO71l2HBdrKSYXaxGgILxYwcSi3i2EjzxRDy+0zyy8s7d+OD5ShFYexgS\n" +
                "rKH3Xx1cxQAJzGGJVx75HHU9GVh3xHwJ7nDm26KzHegG2XPIBXJ2z8vmsSVTWyj0\n" +
                "AjT4kVVapN0f84AKKjyQ7fguCzXGHFV9jmxDx+YH+9HhjIrHSzbDx6+4wyRsxj7S\n" +
                "u+hu/bogJ28nnbTzQwARAQABwsGsBBgBCgAJBYJeC+EAApsCAVcJEGhPrWLcA4+7\n" +
                "wHSgBBkBCgAGBYJeC+EAACEJEEpyNKOhITplFiEEUXksDkji/alOk7kRSnI0o6Eh\n" +
                "OmWnSQgAiu/zdEmHf6Wbwfbs/c6FObfPxGuzLkQr4fZKcqK81MtR1mh1WVLJRgXW\n" +
                "4u8cHtZyH5pThngMcUiyzWsa0g6Jaz8w6sr/Wv3e1qdTCITskMrWCDaoDhD2teAj\n" +
                "mWuk9u8ZBPJ7xhme+Q/UQ90xomQ/NdCJafirk2Ds92p7N7RKSES1KywBhfONJbPw\n" +
                "1TdZ9Mts+DGjkucYbe+ZzPxrLpWXur1BSGEqBtTAGW3dS/xpwBYNlhasXHjYMr4H\n" +
                "eIYYYOx+oR5JgDYoVfp2k0DwK/QXogbja+/Vjv+LrXdNY0t1bA35FNnl637M8iCN\n" +
                "rXvIoRFARbNyge8c/jSWGPLB/tIyNhYhBPLRUKT+mJJdUekVOWhPrWLcA4+7FLwI\n" +
                "AK1GngNMnruxWM4EoghKTSmKNrd6p/d3Wsd+y2019A7Nz+4OydkEDvmNVVhlUcfg\n" +
                "Of2L6Bf63wdN0ho+ODhCuNSqHe6NL1NhdITbMGnDdKb57IIB9CuJFpILn9LZ1Ei6\n" +
                "JPEpmpiSEaL+VJt1fMnfc8jtF8N3WcRVfJsq1aslXe8Npg709YVgm2OXsNWgktl9\n" +
                "fciu4ENTybQGjpN9WTa1aU1nkko6NUoIfjtM+PO4VU7x00M+dTJsYGhnc96EtT8E\n" +
                "fSAIFBKZRAkMBFhEcdkxa8hCKI3+nyI3gTq0TcFST3wy05AmoV7wlgzUAMsW7MV2\n" +
                "NpG7fJul2Q7puKw+udBUc0TCwawEGAEKAAkFglro/4ACmwIBVwkQaE+tYtwDj7vA\n" +
                "dKAEGQEKAAYFglro/4AAIQkQSnI0o6EhOmUWIQRReSwOSOL9qU6TuRFKcjSjoSE6\n" +
                "ZeFHB/92jhUTXrEgho6DYhmVFuXa3NGhAjIyZo3yYHMoL9aZ3DUyjxhAyRDpI2Cr\n" +
                "ahQ4JsPhej2m+3fHWa34/tb5mpHYFWEahQvdWSFCcU7p2NUKcq2zNA6ixO2+fQQh\n" +
                "mbrYR+TFxYmhLjCGUNt14E/XaIL1VxPQOA5KbiRPpa8BsUNlNik9ASPWyn0ZA0rj\n" +
                "J1ZV7nJarXVbuZDEcUDuDm3cA5tup7juB8fTz2BDcg3Ka+OcPEz0GgZfq9K40di3\n" +
                "r9IHLBhNPHieFVIj9j/JyMnTvVOceM3J/Rb0MCWJVbXNBKpRMDibCQh+7fbqyQEM\n" +
                "/zIpmk0TgBpTZZqMP0gxYdWImT1IFiEE8tFQpP6Ykl1R6RU5aE+tYtwDj7tOtggA\n" +
                "hgAqvOB142L2SkS3ZIdwuhAtWLPHCtEwBOqGtP8Z204rqAmbnJymzo77+OT+SScn\n" +
                "DTrwzOUJnCi0qPUxfuxhvHxnBxBIjaoMcF++iKsqF1vf6WuXOjbJ1N8I08pB2nih\n" +
                "t5MxIZ9rMGDeASj79X7I9Jjzsd30OVGfTZyy3VyYPxcJ6n/sZocNmaTv0/F8K3Ti\n" +
                "rSH6JDXdY5zirRi99GJ3R+AL6OzxrChuvLFSEtIRJrW5XVfg3whc0XD+5J9RsHoL\n" +
                "33ub9ZhQHFKsjrf0nGYbEFwMhSdysfTYYMbwKi0CcQeQtPP0Y87zSryajDMFXQS0\n" +
                "exdvhN4AXDlPlB3Rrkj7CQ==\n" +
                "=qQpG\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigPredatesPrimaryKey = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJYaEaAACEJEGhPrWLcA4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwD\n" +
                "j7ttqgf9Gp4T5Q19cNL9Eyz1nlw11HDHT1wxfGHU5li76y7oo4Jqim15sEPDJWmc\n" +
                "IpYVrczpCI95aCuaE6yfzpjZlXMzftwex3DjM98vyZH4W9teKcOnpAVjn3dLoQJA\n" +
                "i4fiq3VaLgl+1OYOwu3DmwGKJZubHM3oPia9pbuyvL5Scvx+QCG0AVnssnt2QswG\n" +
                "uU6J35QgBdjG2iC043sUoyxTSk929iamdQnOGchjcaATb4E4+HvtkRy4IirKxiKK\n" +
                "c535BHJRLgWQzUcDDZ5kHf3SPLTNsigFFEwUyf5voFcn/DSMWSzPaVecaafTVJW2\n" +
                "u8G1R5mjuxDRup8p//X1BSk1FpSmvw==\n" +
                "=3/dv\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigKeyIsValid = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJa564AACEJEGhPrWLcA4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwD\n" +
                "j7ufRgf/QOsaJZgQaQ5daQrfBItOEcW+5acgY1TCwMVmc/nzBqC32TOvMaM3dypf\n" +
                "wJbqzxHQIes+ivKDF872VWlMA2BErifpdsogbS0pdik/qU+AjMhr188xKpZKG/IY\n" +
                "6BtuUPeSpsimx3UeEN3kt79fMtewBo0EXo3ujCyPpIF/9Vpd7L9jlJSvRBuM0/aR\n" +
                "gbRsclEw4JZ98B3t7F3rLmx+F57Zre0ctzT4tHE6IaCYpEClr6Tepj/UxExYOt2l\n" +
                "hKgVN8Wsuug7XYdOFmxqrV967m3CTnF8AspmxwgKK6NXjVLplfqij7Rp2URPWrWn\n" +
                "Pp3CQRGUWJdMeMY9P1MpFq6XiXtftw==\n" +
                "=Ld1q\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigKeyIsRevoked = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJdP4iAACEJEGhPrWLcA4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwD\n" +
                "j7sYXQf8CZw6Kx4oyI8ZJ2c9RjVZmUFEirAoXH7oYA+Ye+wSAY9OtqE/x2SOYaC6\n" +
                "QHiB93/wkvpqCVkLy2lenzpD7WXLbuFZ+/5jXp1o+sVHXfLSWo6pfIhOjj9FSr8x\n" +
                "qqlqUfKwkbA6WYgju+qKC35SYdSptix7unaFkO41UdsM8wGQh880HSRMBMFPzg07\n" +
                "3hMNYXoEJjFlIkxJSMu2WL7N0Q/4xE2iJftsQjUYAtJ/C/YK2I6dhW+CZremnv5R\n" +
                "/8W+oH5Q63lYU8YL4wYnJQvkHjKs/kjLpoPmqL8kdHjndSpU+KOYr5w61XuEp2hp\n" +
                "r8trtljVaVIQX2rYawSlqKkWXt0yag==\n" +
                "=xVd8\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigKeyIsRevalidated = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJe/cFVACEJEGhPrWLcA4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwD\n" +
                "j7vmhQf/UB456IXc8ub8HTExab1d5KqOGSUWpwIznTu8Wk8YuzWKEE8ZeZvPmv8K\n" +
                "iJfBoOx59YrlOfpLAKcTR9Ql+IFbWsIkqPxX7U1SGldhfQm7iaK5Dn6+mmQFOz/s\n" +
                "ZCIavWJ7opsp11JmQAt4FFojv789YswaS7VI1zjDj7EeRiATtzna/GqCYgeCM0cc\n" +
                "sIe/1j1H2oh9YvYIpPMSGDJPo7T1Ji4Ie3iEQEYNYPuw1Hb7gWYncHXZGJq1nDf/\n" +
                "WAoI9gSFagpsPW0k9cfEAOVNLNYSyi0CSnQWSjq8THbHKiLPFwsP3hvT2oHycWbK\n" +
                "u5SfXaTsbMeVQJNdjCNsHq2bOXPGLw==\n" +
                "=2BW4\n" +
                "-----END PGP ARMORED FILE-----\n";

        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(keyWithSoftRev);
        PGPSignature predatesPrimaryKey = SignatureUtils.readSignatures(sigPredatesPrimaryKey).get(0);
        PGPSignature keyIsValid = SignatureUtils.readSignatures(sigKeyIsValid).get(0);
        PGPSignature keyIsRevoked = SignatureUtils.readSignatures(sigKeyIsRevoked).get(0);
        PGPSignature keyIsRevalidated = SignatureUtils.readSignatures(sigKeyIsRevalidated).get(0);
        Policy policy = PGPainless.getPolicy();
        String data = "Hello, World";

        // Sig not valid, as it predates the signing key creation time
        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                predatesPrimaryKey, getSignedData(data), publicKeys, policy, predatesPrimaryKey.getCreationTime()),
                "Signature predates primary key creation date");

        // Sig valid
        assertDoesNotThrow(() -> SignatureChainValidator.validateSignatureChain(
                keyIsValid, getSignedData(data), publicKeys, policy, keyIsValid.getCreationTime()),
                "Signature is valid");

        // Sig not valid, as the signing key is revoked
        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                keyIsRevoked, getSignedData(data), publicKeys, policy, keyIsRevoked.getCreationTime()),
                "Signing key is revoked at this point");

        // Sig valid, as the signing key is revalidated
        assertDoesNotThrow(() -> SignatureChainValidator.validateSignatureChain(
                keyIsRevalidated, getSignedData(data), publicKeys, policy, keyIsRevalidated.getCreationTime()),
                "Signature is valid, as signing key is revalidated");
    }

    /**
     * Subkey signs, primary key is soft revoked with reason: superseded.
     *
     * @see <a href="https://tests.sequoia-pgp.org/#Key_revocation_test__subkey_signs__primary_key_is_revoked__revoked__superseded">Sequoia Test Suite</a>
     */
    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void testSubkeySignsPrimaryKeyIsSoftRevokedSuperseded(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

        String key = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "xsBNBFpJegABCAC1ePFquP0135m8DYhcybhv7l+ecojitFOd/jRM7hCczIqKgalD\n" +
                "1Ro1gNr3VmH6FjRIKIvGT+sOzCKne1v3KyAAPoxtwxjkATTKdOGo15I6v5ZjmO1d\n" +
                "rLQOLSt1TF7XbQSt+ns6PUZWJL907DvECUU5b9FkNUqfQ14QqY+gi7MOyAQez3b7\n" +
                "Pg5Cyz/kVWQ6TSMW/myDEDEertQ4rDBsptEDFHCC2+iF4hO2LqfiCriu5qyLcKCQ\n" +
                "pd6dEuwJQ/jjT0D9A9Fwf+i04x6ZPKSU9oNAWqn8OSAq3/0B/hu9V+0U0iHPnJxe\n" +
                "quykvJk7maxhiGhxBWYXTvDJmoon0NOles7LABEBAAHCwIcEIAEKABoFglwqrYAT\n" +
                "HQFLZXkgaXMgc3VwZXJzZWRlZAAhCRBoT61i3AOPuxYhBPLRUKT+mJJdUekVOWhP\n" +
                "rWLcA4+76+wH/1NmN/Qma5FTxmSWEcfH2ynKhwejKp8p8O7+y/uq1FlUwRzChzeX\n" +
                "kd9w099uODMasxGaNSJU1mh5N+1oulyHrSyWFRWqDnQUnDx3IiPapK/j85udkJdo\n" +
                "WfdTcxaS2C9Yo4S77cPwkbFLmEQ2Ovs5zjj0Q+mfoZNM+KJcsnOoJ+eeOE2GNA3x\n" +
                "5TWvw0QXBfyW74MZHc0UE82ixcG6g4KbrI6W544EixY5vu3IxVsxiL66zy27A8ha\n" +
                "EDdBWS8kc8UQ2cRveuqZwRsWcrh/2iHHShY/5zBOdQ1PL++ubwkteNSU9SsXjjDM\n" +
                "oWm1RGy7/bagPPtqBnRMQ20vvW+3oBYxyd7CwHwEHwEKAA8Fgl4L4QACFQoCmwMC\n" +
                "HgEAIQkQaE+tYtwDj7sWIQTy0VCk/piSXVHpFTloT61i3AOPu8ffB/9Q60dg60qh\n" +
                "A2rPnd/1dCL2B+c8RWnq44PpijE3gA1RQvcRQE5jNzMSo/MnG0mSL5wHeTsjSd/D\n" +
                "RI3nHP06rs6Qub11NoKhNuya3maz9gyzeZMc/jNib83/BzFCrxsSQm+9WHurxXeW\n" +
                "XOPMLZs3xS/jG0EDtCJ2Fm4UF19fcIydwN/ssF4NGpfCY82+wTSx4joI3cRKObCF\n" +
                "JaaBgG5nl+eFr7cfjEIuqCJCaQsXiqBe7d6V3KqN18t+CgSaybMZXcysQ/USxEkL\n" +
                "hIB2pOZwcz4E3TTFgxRAxcr4cs4Bd2PRz3Z5FKTzo0ma/Ft0UfFJR+fCcs55+n6k\n" +
                "C9K0y/E7BY2hwsB8BB8BCgAPBYJaSXoAAhUKApsDAh4BACEJEGhPrWLcA4+7FiEE\n" +
                "8tFQpP6Ykl1R6RU5aE+tYtwDj7uqDQf7BqTD6GNTwXPOt/0kHQPYmbdItX+pWP+o\n" +
                "3jaB6VTHDXcn27bttA5M82EXZfae4+bC1dMB+1uLal4ciVgO9ImJC9Nws5fc3JH4\n" +
                "R5uuSvpjzjudkJsGu3cAKE3hwiT93Mi6t6ENpLCDSxqxzAmfoOQbVJYWY7gP7Z4C\n" +
                "j0IAP29aprEc0JWoMjHKpKgYF6u0sWgHWBuEXk/6o6GYb2HZYK4ycpY2WXKgVhy7\n" +
                "/iQDYO1FOfcWQXHVGLn8OzILjobKohNenTT20ZhAASi3LUDSDMTQfxSSVt0nhzWu\n" +
                "XJJ4R8PzUVeRJ0A0oMyjZVHivHC6GwMsiQuSUTx8e/GnOByOqfGne80SanVsaWV0\n" +
                "QGV4YW1wbGUub3JnwsBzBBMBCgAGBYJaSXoAACEJEGhPrWLcA4+7FiEE8tFQpP6Y\n" +
                "kl1R6RU5aE+tYtwDj7tDfQf+PnxsIFu/0juKBUjjtAYfRzkrrYtMepPjtaTvGfo1\n" +
                "SzUkX/6F/GjdSeVg5Iq6YcBrj8c+cB3EoZpHnScTgWQHwceWQLd9HhbgTrUNvW1e\n" +
                "g2CVzN0RBuYMtWu9JM4pH7ssJW1NmN+/N9B67qb2y+JfBwH/la508NzCrl3xWTxj\n" +
                "T5wNy+FGkNZg23s/0qlO2uxCjc+mRAuAlp5EmTOVWOIBbM0xttjBOx39ZmWWQKJZ\n" +
                "0nrFjK1jppHqazwWWNX7RHkK81tlbSUtOPoTIJDz38NaiyMcZH3p9okN3DU4XtF+\n" +
                "oE18M+Z/E0xUQmumbkajFzcUjmd7enozP5BnGESzdNS5Xc7ATQRaSsuAAQgAykb8\n" +
                "tqlWXtqHGGkBqAq3EnpmvBqrKvqejjtZKAXqEszJ9NlibCGUuLwnNOVOR/hcOUlO\n" +
                "GH+cyMcApBWJB+7d/83K1eCCdv88nDFVav7hKLKlEBbZJNHgHpJ313pletzCR4x3\n" +
                "STEISrEtO71l2HBdrKSYXaxGgILxYwcSi3i2EjzxRDy+0zyy8s7d+OD5ShFYexgS\n" +
                "rKH3Xx1cxQAJzGGJVx75HHU9GVh3xHwJ7nDm26KzHegG2XPIBXJ2z8vmsSVTWyj0\n" +
                "AjT4kVVapN0f84AKKjyQ7fguCzXGHFV9jmxDx+YH+9HhjIrHSzbDx6+4wyRsxj7S\n" +
                "u+hu/bogJ28nnbTzQwARAQABwsGsBBgBCgAJBYJeC+EAApsCAVcJEGhPrWLcA4+7\n" +
                "wHSgBBkBCgAGBYJeC+EAACEJEEpyNKOhITplFiEEUXksDkji/alOk7kRSnI0o6Eh\n" +
                "OmWnSQgAiu/zdEmHf6Wbwfbs/c6FObfPxGuzLkQr4fZKcqK81MtR1mh1WVLJRgXW\n" +
                "4u8cHtZyH5pThngMcUiyzWsa0g6Jaz8w6sr/Wv3e1qdTCITskMrWCDaoDhD2teAj\n" +
                "mWuk9u8ZBPJ7xhme+Q/UQ90xomQ/NdCJafirk2Ds92p7N7RKSES1KywBhfONJbPw\n" +
                "1TdZ9Mts+DGjkucYbe+ZzPxrLpWXur1BSGEqBtTAGW3dS/xpwBYNlhasXHjYMr4H\n" +
                "eIYYYOx+oR5JgDYoVfp2k0DwK/QXogbja+/Vjv+LrXdNY0t1bA35FNnl637M8iCN\n" +
                "rXvIoRFARbNyge8c/jSWGPLB/tIyNhYhBPLRUKT+mJJdUekVOWhPrWLcA4+7FLwI\n" +
                "AK1GngNMnruxWM4EoghKTSmKNrd6p/d3Wsd+y2019A7Nz+4OydkEDvmNVVhlUcfg\n" +
                "Of2L6Bf63wdN0ho+ODhCuNSqHe6NL1NhdITbMGnDdKb57IIB9CuJFpILn9LZ1Ei6\n" +
                "JPEpmpiSEaL+VJt1fMnfc8jtF8N3WcRVfJsq1aslXe8Npg709YVgm2OXsNWgktl9\n" +
                "fciu4ENTybQGjpN9WTa1aU1nkko6NUoIfjtM+PO4VU7x00M+dTJsYGhnc96EtT8E\n" +
                "fSAIFBKZRAkMBFhEcdkxa8hCKI3+nyI3gTq0TcFST3wy05AmoV7wlgzUAMsW7MV2\n" +
                "NpG7fJul2Q7puKw+udBUc0TCwawEGAEKAAkFglro/4ACmwIBVwkQaE+tYtwDj7vA\n" +
                "dKAEGQEKAAYFglro/4AAIQkQSnI0o6EhOmUWIQRReSwOSOL9qU6TuRFKcjSjoSE6\n" +
                "ZeFHB/92jhUTXrEgho6DYhmVFuXa3NGhAjIyZo3yYHMoL9aZ3DUyjxhAyRDpI2Cr\n" +
                "ahQ4JsPhej2m+3fHWa34/tb5mpHYFWEahQvdWSFCcU7p2NUKcq2zNA6ixO2+fQQh\n" +
                "mbrYR+TFxYmhLjCGUNt14E/XaIL1VxPQOA5KbiRPpa8BsUNlNik9ASPWyn0ZA0rj\n" +
                "J1ZV7nJarXVbuZDEcUDuDm3cA5tup7juB8fTz2BDcg3Ka+OcPEz0GgZfq9K40di3\n" +
                "r9IHLBhNPHieFVIj9j/JyMnTvVOceM3J/Rb0MCWJVbXNBKpRMDibCQh+7fbqyQEM\n" +
                "/zIpmk0TgBpTZZqMP0gxYdWImT1IFiEE8tFQpP6Ykl1R6RU5aE+tYtwDj7tOtggA\n" +
                "hgAqvOB142L2SkS3ZIdwuhAtWLPHCtEwBOqGtP8Z204rqAmbnJymzo77+OT+SScn\n" +
                "DTrwzOUJnCi0qPUxfuxhvHxnBxBIjaoMcF++iKsqF1vf6WuXOjbJ1N8I08pB2nih\n" +
                "t5MxIZ9rMGDeASj79X7I9Jjzsd30OVGfTZyy3VyYPxcJ6n/sZocNmaTv0/F8K3Ti\n" +
                "rSH6JDXdY5zirRi99GJ3R+AL6OzxrChuvLFSEtIRJrW5XVfg3whc0XD+5J9RsHoL\n" +
                "33ub9ZhQHFKsjrf0nGYbEFwMhSdysfTYYMbwKi0CcQeQtPP0Y87zSryajDMFXQS0\n" +
                "exdvhN4AXDlPlB3Rrkj7CQ==\n" +
                "=qQpG\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigPredatesPrimaryKey = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJYaEaAACEJEEpyNKOhITplFiEEUXksDkji/alOk7kRSnI0o6Eh\n" +
                "OmVtqgf/YSG+b8lY01/4oCrHoNMECDDbpI5+8WkeT0CcdlEd5TGj3AHesT6H6XmL\n" +
                "ZxaHHOwtkuDh0bIAiYGl36e4ult5XZQhFIwUXGde6myLE+fpCGsBJwNu+TDIrbg3\n" +
                "PGqnVZNlcU+2sP5JhJfAn8VtLENuHkbIC3+kH8xBIrkPTc0rbNBgyzX5eFO20U0D\n" +
                "bHCCjfjVDpZ8l7N2NlsRYvU0kTzN5GvwbS1HnMOovF9ZKkEpzxxw6IRJIapaE2L9\n" +
                "adMKIRAqrIIjfj6Z9nETd1nZE79t1zSw1trfArPaJQr46krgh1ocLQoD/c+PhB9l\n" +
                "sRxQBnWERgQaDJByq0kwKSnwWAsyxw==\n" +
                "=SDmD\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigSubkeyNotBound = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJa564AACEJEEpyNKOhITplFiEEUXksDkji/alOk7kRSnI0o6Eh\n" +
                "OmWfRgf9ECjIviU1pN0GiMZGci3Vce2b42LIqH0JZApOeRDpcyXgxi3/CmdaewpT\n" +
                "w9l18gsXhioRg4xUzMFrYSgyYZ9VajFggMjbeX5dSV3rsOSJSiEEyDbeGi0TcA/Y\n" +
                "GUifX4EfKx5X5nI/wevnYjmruDp9SqaPLHIZK1soOoPzueZ8wKyJ9A4vVG4bvxVX\n" +
                "FnwBf6mRE/0Z8IoHlRJdq0fSzW4RgX8KAtK8SfyGOnk7LDaevVuL6iE5v0Gsu0oh\n" +
                "cHlI6Llm97EVxP93KZ1J7TQIi/a6PUJb5XCIw0K/iyuNuAzETgm8LVJyn6UwL4ym\n" +
                "KcNieOK8Qcoivq0kCYuv/0Tbk13jVQ==\n" +
                "=5hOz\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigKeyRevoked = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJdP4iAACEJEEpyNKOhITplFiEEUXksDkji/alOk7kRSnI0o6Eh\n" +
                "OmUYXQf/dGNZay40bZEpcnxYl+Kq+gRQESeDhg/xOfGfSCLQncMH+UYPaUKANC2g\n" +
                "CfMNN1wd8ZWrvgyTVo3TVfK1P1RYa9nrvKoKN3bjsFcY6V7VciPW58xVNsuxsEEC\n" +
                "GEH96TQy+FsP680tRnzQ3Dbw/JT6o6Xi+HLf4JVFceapBgyth61E5gN5w3azxVFr\n" +
                "GfwIfHvepOjCIq9tRZsRFEBp3XVZ/AF+zQMG5nfIVSm1kVtZjb7KXc3Bj48DVrmb\n" +
                "XLxPJz7PLY0cgOsXXxROIdtFT+mbVQg2j247hxnhItwtLeQrafb5T8ibeihRlkhK\n" +
                "1tfKv31EP8tAVqgTjw+qD32bH9h77w==\n" +
                "=MOaJ\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigKeyValid = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJe/cFVACEJEEpyNKOhITplFiEEUXksDkji/alOk7kRSnI0o6Eh\n" +
                "OmXmhQf+LjM2vmdKYnxfVy40Vcdoy2Jov/ZD2RSMFff+fIoCXmWfEetila7v5xHj\n" +
                "ZXq6aevTEN1vgW3T6Q1OjFhnGpMl9wvya9mszfn5BBKukFtLkHeay0PtYuUcrfJC\n" +
                "UIQCx9PFZzgRJFyGsCqrXBc1VIe2DV3d8dq74unTeCEmWdvAZKdjoUYzRohMtcZ+\n" +
                "0QctCCJE1kRFJuH/TIdxxwKPtBZfOolSlpS0Z5xxa2sILqUvQ2Dq3hBctUM4g6hB\n" +
                "Y8uafI8qIMwWl4DQDzPpQ917d6J+GCdN0Aib6ZOsvmgR5wrBOFiDpRJ/W9W6+rgs\n" +
                "I5V/t2y6h6gaHbanggc0cMOaMTtEKQ==\n" +
                "=lkHs\n" +
                "-----END PGP ARMORED FILE-----\n";

        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(key);
        PGPSignature predatesPrimaryKey = SignatureUtils.readSignatures(sigPredatesPrimaryKey).get(0);
        PGPSignature keyNotBound = SignatureUtils.readSignatures(sigSubkeyNotBound).get(0);
        PGPSignature keyRevoked = SignatureUtils.readSignatures(sigKeyRevoked).get(0);
        PGPSignature valid = SignatureUtils.readSignatures(sigKeyValid).get(0);

        Policy policy = PGPainless.getPolicy();
        String data = "Hello, World";
        Date validationDate = new Date();

        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                predatesPrimaryKey, getSignedData(data), publicKeys, policy, validationDate),
                "Signature predates primary key creation date");
        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                keyNotBound, getSignedData(data), publicKeys, policy, validationDate),
                "Signing key is not bound at this point");
        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                keyRevoked, getSignedData(data), publicKeys, policy, validationDate),
                "Signing key is revoked at this point");
        assertDoesNotThrow(() ->
                        SignatureChainValidator.validateSignatureChain(
                                valid, getSignedData(data), publicKeys, policy, validationDate),
                "Signing key is revalidated");
    }

    /**
     * Primary key signs and is soft revoked with reason: retired.
     *
     * @see <a href="https://tests.sequoia-pgp.org/#Key_revocation_test__primary_key_signs_and_is_revoked__revoked__key_retired">Sequoia Test Suite</a>
     */
    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void testPrimaryKeySignsAndIsSoftRevokedRetired(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

        String key = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "xsBNBFpJegABCAC1ePFquP0135m8DYhcybhv7l+ecojitFOd/jRM7hCczIqKgalD\n" +
                "1Ro1gNr3VmH6FjRIKIvGT+sOzCKne1v3KyAAPoxtwxjkATTKdOGo15I6v5ZjmO1d\n" +
                "rLQOLSt1TF7XbQSt+ns6PUZWJL907DvECUU5b9FkNUqfQ14QqY+gi7MOyAQez3b7\n" +
                "Pg5Cyz/kVWQ6TSMW/myDEDEertQ4rDBsptEDFHCC2+iF4hO2LqfiCriu5qyLcKCQ\n" +
                "pd6dEuwJQ/jjT0D9A9Fwf+i04x6ZPKSU9oNAWqn8OSAq3/0B/hu9V+0U0iHPnJxe\n" +
                "quykvJk7maxhiGhxBWYXTvDJmoon0NOles7LABEBAAHCwJcEIAEKACoFglwqrYAj\n" +
                "HQNLZXkgaXMgcmV0aXJlZCBhbmQgbm8gbG9uZ2VyIHVzZWQAIQkQaE+tYtwDj7sW\n" +
                "IQTy0VCk/piSXVHpFTloT61i3AOPu1b6CACO+RvQVt44EMEFm2H33igJ3UxYW0Sj\n" +
                "w8ZoFtst3kl9cP1hNxKPg8wv8tQqIk9+HOxnYe1Qc6Rv+In0ctQFrk4NwQxySpnm\n" +
                "7JA6keRluIkl8aPd2YBtmba0iTXzSOwtaADlHbGss8TYxLxCug/db2nzbw+yKAug\n" +
                "HkP0PmDRQcPwta8JyH/Wm9jiP6HoHReOs580tOsgLU7mG6CP+Oyn3egMvszbZD3A\n" +
                "/z8r85kYv/KDLGzG1T7wsDXqwC9OUDMN31p4S5V6aHJhrqfHYwOlxfRagddoLOWt\n" +
                "xAn+PKWcmu2JKwbBgXxAzLZpAW8wcOsfXAzPEA3hX+rFtPUl2jyUr5pcwsB8BB8B\n" +
                "CgAPBYJeC+EAAhUKApsDAh4BACEJEGhPrWLcA4+7FiEE8tFQpP6Ykl1R6RU5aE+t\n" +
                "YtwDj7vH3wf/UOtHYOtKoQNqz53f9XQi9gfnPEVp6uOD6YoxN4ANUUL3EUBOYzcz\n" +
                "EqPzJxtJki+cB3k7I0nfw0SN5xz9Oq7OkLm9dTaCoTbsmt5ms/YMs3mTHP4zYm/N\n" +
                "/wcxQq8bEkJvvVh7q8V3llzjzC2bN8Uv4xtBA7QidhZuFBdfX3CMncDf7LBeDRqX\n" +
                "wmPNvsE0seI6CN3ESjmwhSWmgYBuZ5fnha+3H4xCLqgiQmkLF4qgXu3eldyqjdfL\n" +
                "fgoEmsmzGV3MrEP1EsRJC4SAdqTmcHM+BN00xYMUQMXK+HLOAXdj0c92eRSk86NJ\n" +
                "mvxbdFHxSUfnwnLOefp+pAvStMvxOwWNocLAfAQfAQoADwWCWkl6AAIVCgKbAwIe\n" +
                "AQAhCRBoT61i3AOPuxYhBPLRUKT+mJJdUekVOWhPrWLcA4+7qg0H+wakw+hjU8Fz\n" +
                "zrf9JB0D2Jm3SLV/qVj/qN42gelUxw13J9u27bQOTPNhF2X2nuPmwtXTAftbi2pe\n" +
                "HIlYDvSJiQvTcLOX3NyR+Eebrkr6Y847nZCbBrt3AChN4cIk/dzIurehDaSwg0sa\n" +
                "scwJn6DkG1SWFmO4D+2eAo9CAD9vWqaxHNCVqDIxyqSoGBertLFoB1gbhF5P+qOh\n" +
                "mG9h2WCuMnKWNllyoFYcu/4kA2DtRTn3FkFx1Ri5/DsyC46GyqITXp009tGYQAEo\n" +
                "ty1A0gzE0H8UklbdJ4c1rlySeEfD81FXkSdANKDMo2VR4rxwuhsDLIkLklE8fHvx\n" +
                "pzgcjqnxp3vNEmp1bGlldEBleGFtcGxlLm9yZ8LAcwQTAQoABgWCWkl6AAAhCRBo\n" +
                "T61i3AOPuxYhBPLRUKT+mJJdUekVOWhPrWLcA4+7Q30H/j58bCBbv9I7igVI47QG\n" +
                "H0c5K62LTHqT47Wk7xn6NUs1JF/+hfxo3UnlYOSKumHAa4/HPnAdxKGaR50nE4Fk\n" +
                "B8HHlkC3fR4W4E61Db1tXoNglczdEQbmDLVrvSTOKR+7LCVtTZjfvzfQeu6m9svi\n" +
                "XwcB/5WudPDcwq5d8Vk8Y0+cDcvhRpDWYNt7P9KpTtrsQo3PpkQLgJaeRJkzlVji\n" +
                "AWzNMbbYwTsd/WZllkCiWdJ6xYytY6aR6ms8FljV+0R5CvNbZW0lLTj6EyCQ89/D\n" +
                "WosjHGR96faJDdw1OF7RfqBNfDPmfxNMVEJrpm5Goxc3FI5ne3p6Mz+QZxhEs3TU\n" +
                "uV3OwE0EWkrLgAEIAMpG/LapVl7ahxhpAagKtxJ6Zrwaqyr6no47WSgF6hLMyfTZ\n" +
                "YmwhlLi8JzTlTkf4XDlJThh/nMjHAKQViQfu3f/NytXggnb/PJwxVWr+4SiypRAW\n" +
                "2STR4B6Sd9d6ZXrcwkeMd0kxCEqxLTu9ZdhwXaykmF2sRoCC8WMHEot4thI88UQ8\n" +
                "vtM8svLO3fjg+UoRWHsYEqyh918dXMUACcxhiVce+Rx1PRlYd8R8Ce5w5tuisx3o\n" +
                "BtlzyAVyds/L5rElU1so9AI0+JFVWqTdH/OACio8kO34Lgs1xhxVfY5sQ8fmB/vR\n" +
                "4YyKx0s2w8evuMMkbMY+0rvobv26ICdvJ52080MAEQEAAcLBrAQYAQoACQWCXgvh\n" +
                "AAKbAgFXCRBoT61i3AOPu8B0oAQZAQoABgWCXgvhAAAhCRBKcjSjoSE6ZRYhBFF5\n" +
                "LA5I4v2pTpO5EUpyNKOhITplp0kIAIrv83RJh3+lm8H27P3OhTm3z8Rrsy5EK+H2\n" +
                "SnKivNTLUdZodVlSyUYF1uLvHB7Wch+aU4Z4DHFIss1rGtIOiWs/MOrK/1r93tan\n" +
                "UwiE7JDK1gg2qA4Q9rXgI5lrpPbvGQTye8YZnvkP1EPdMaJkPzXQiWn4q5Ng7Pdq\n" +
                "eze0SkhEtSssAYXzjSWz8NU3WfTLbPgxo5LnGG3vmcz8ay6Vl7q9QUhhKgbUwBlt\n" +
                "3Uv8acAWDZYWrFx42DK+B3iGGGDsfqEeSYA2KFX6dpNA8Cv0F6IG42vv1Y7/i613\n" +
                "TWNLdWwN+RTZ5et+zPIgja17yKERQEWzcoHvHP40lhjywf7SMjYWIQTy0VCk/piS\n" +
                "XVHpFTloT61i3AOPuxS8CACtRp4DTJ67sVjOBKIISk0pija3eqf3d1rHfsttNfQO\n" +
                "zc/uDsnZBA75jVVYZVHH4Dn9i+gX+t8HTdIaPjg4QrjUqh3ujS9TYXSE2zBpw3Sm\n" +
                "+eyCAfQriRaSC5/S2dRIuiTxKZqYkhGi/lSbdXzJ33PI7RfDd1nEVXybKtWrJV3v\n" +
                "DaYO9PWFYJtjl7DVoJLZfX3IruBDU8m0Bo6TfVk2tWlNZ5JKOjVKCH47TPjzuFVO\n" +
                "8dNDPnUybGBoZ3PehLU/BH0gCBQSmUQJDARYRHHZMWvIQiiN/p8iN4E6tE3BUk98\n" +
                "MtOQJqFe8JYM1ADLFuzFdjaRu3ybpdkO6bisPrnQVHNEwsGsBBgBCgAJBYJa6P+A\n" +
                "ApsCAVcJEGhPrWLcA4+7wHSgBBkBCgAGBYJa6P+AACEJEEpyNKOhITplFiEEUXks\n" +
                "Dkji/alOk7kRSnI0o6EhOmXhRwf/do4VE16xIIaOg2IZlRbl2tzRoQIyMmaN8mBz\n" +
                "KC/Wmdw1Mo8YQMkQ6SNgq2oUOCbD4Xo9pvt3x1mt+P7W+ZqR2BVhGoUL3VkhQnFO\n" +
                "6djVCnKtszQOosTtvn0EIZm62EfkxcWJoS4whlDbdeBP12iC9VcT0DgOSm4kT6Wv\n" +
                "AbFDZTYpPQEj1sp9GQNK4ydWVe5yWq11W7mQxHFA7g5t3AObbqe47gfH089gQ3IN\n" +
                "ymvjnDxM9BoGX6vSuNHYt6/SBywYTTx4nhVSI/Y/ycjJ071TnHjNyf0W9DAliVW1\n" +
                "zQSqUTA4mwkIfu326skBDP8yKZpNE4AaU2WajD9IMWHViJk9SBYhBPLRUKT+mJJd\n" +
                "UekVOWhPrWLcA4+7TrYIAIYAKrzgdeNi9kpEt2SHcLoQLVizxwrRMATqhrT/GdtO\n" +
                "K6gJm5ycps6O+/jk/kknJw068MzlCZwotKj1MX7sYbx8ZwcQSI2qDHBfvoirKhdb\n" +
                "3+lrlzo2ydTfCNPKQdp4obeTMSGfazBg3gEo+/V+yPSY87Hd9DlRn02cst1cmD8X\n" +
                "Cep/7GaHDZmk79PxfCt04q0h+iQ13WOc4q0YvfRid0fgC+js8awobryxUhLSESa1\n" +
                "uV1X4N8IXNFw/uSfUbB6C997m/WYUBxSrI639JxmGxBcDIUncrH02GDG8CotAnEH\n" +
                "kLTz9GPO80q8mowzBV0EtHsXb4TeAFw5T5Qd0a5I+wk=\n" +
                "=7j+m\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigPredatesPrimaryKey = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJYaEaAACEJEGhPrWLcA4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwD\n" +
                "j7ttqgf9Gp4T5Q19cNL9Eyz1nlw11HDHT1wxfGHU5li76y7oo4Jqim15sEPDJWmc\n" +
                "IpYVrczpCI95aCuaE6yfzpjZlXMzftwex3DjM98vyZH4W9teKcOnpAVjn3dLoQJA\n" +
                "i4fiq3VaLgl+1OYOwu3DmwGKJZubHM3oPia9pbuyvL5Scvx+QCG0AVnssnt2QswG\n" +
                "uU6J35QgBdjG2iC043sUoyxTSk929iamdQnOGchjcaATb4E4+HvtkRy4IirKxiKK\n" +
                "c535BHJRLgWQzUcDDZ5kHf3SPLTNsigFFEwUyf5voFcn/DSMWSzPaVecaafTVJW2\n" +
                "u8G1R5mjuxDRup8p//X1BSk1FpSmvw==\n" +
                "=3/dv\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigValid = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJa564AACEJEGhPrWLcA4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwD\n" +
                "j7ufRgf/QOsaJZgQaQ5daQrfBItOEcW+5acgY1TCwMVmc/nzBqC32TOvMaM3dypf\n" +
                "wJbqzxHQIes+ivKDF872VWlMA2BErifpdsogbS0pdik/qU+AjMhr188xKpZKG/IY\n" +
                "6BtuUPeSpsimx3UeEN3kt79fMtewBo0EXo3ujCyPpIF/9Vpd7L9jlJSvRBuM0/aR\n" +
                "gbRsclEw4JZ98B3t7F3rLmx+F57Zre0ctzT4tHE6IaCYpEClr6Tepj/UxExYOt2l\n" +
                "hKgVN8Wsuug7XYdOFmxqrV967m3CTnF8AspmxwgKK6NXjVLplfqij7Rp2URPWrWn\n" +
                "Pp3CQRGUWJdMeMY9P1MpFq6XiXtftw==\n" +
                "=Ld1q\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigRevoked = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJdP4iAACEJEGhPrWLcA4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwD\n" +
                "j7sYXQf8CZw6Kx4oyI8ZJ2c9RjVZmUFEirAoXH7oYA+Ye+wSAY9OtqE/x2SOYaC6\n" +
                "QHiB93/wkvpqCVkLy2lenzpD7WXLbuFZ+/5jXp1o+sVHXfLSWo6pfIhOjj9FSr8x\n" +
                "qqlqUfKwkbA6WYgju+qKC35SYdSptix7unaFkO41UdsM8wGQh880HSRMBMFPzg07\n" +
                "3hMNYXoEJjFlIkxJSMu2WL7N0Q/4xE2iJftsQjUYAtJ/C/YK2I6dhW+CZremnv5R\n" +
                "/8W+oH5Q63lYU8YL4wYnJQvkHjKs/kjLpoPmqL8kdHjndSpU+KOYr5w61XuEp2hp\n" +
                "r8trtljVaVIQX2rYawSlqKkWXt0yag==\n" +
                "=xVd8\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigReLegitimized = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "wsBzBAABCgAGBYJe/cFVACEJEGhPrWLcA4+7FiEE8tFQpP6Ykl1R6RU5aE+tYtwD\n" +
                "j7vmhQf/UB456IXc8ub8HTExab1d5KqOGSUWpwIznTu8Wk8YuzWKEE8ZeZvPmv8K\n" +
                "iJfBoOx59YrlOfpLAKcTR9Ql+IFbWsIkqPxX7U1SGldhfQm7iaK5Dn6+mmQFOz/s\n" +
                "ZCIavWJ7opsp11JmQAt4FFojv789YswaS7VI1zjDj7EeRiATtzna/GqCYgeCM0cc\n" +
                "sIe/1j1H2oh9YvYIpPMSGDJPo7T1Ji4Ie3iEQEYNYPuw1Hb7gWYncHXZGJq1nDf/\n" +
                "WAoI9gSFagpsPW0k9cfEAOVNLNYSyi0CSnQWSjq8THbHKiLPFwsP3hvT2oHycWbK\n" +
                "u5SfXaTsbMeVQJNdjCNsHq2bOXPGLw==\n" +
                "=2BW4\n" +
                "-----END PGP ARMORED FILE-----\n";

        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(key);
        PGPSignature predatesPrimaryKey = SignatureUtils.readSignatures(sigPredatesPrimaryKey).get(0);
        PGPSignature valid = SignatureUtils.readSignatures(sigValid).get(0);
        PGPSignature revoked = SignatureUtils.readSignatures(sigRevoked).get(0);
        PGPSignature revalidated = SignatureUtils.readSignatures(sigReLegitimized).get(0);

        Policy policy = PGPainless.getPolicy();
        Date validationDate = new Date();
        String data = "Hello, World";

        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                predatesPrimaryKey, getSignedData(data), publicKeys, policy, validationDate),
                "Signature predates primary key creation date");
        assertDoesNotThrow(() -> SignatureChainValidator.validateSignatureChain(
                valid, getSignedData(data), publicKeys, policy, validationDate),
                "Signature is valid");
        assertThrows(SignatureValidationException.class, () ->
                        SignatureChainValidator.validateSignatureChain(
                                revoked, getSignedData(data), publicKeys, policy, validationDate),
                "Primary key is revoked");
        assertDoesNotThrow(() -> SignatureChainValidator.validateSignatureChain(
                revalidated, getSignedData(data), publicKeys, policy, validationDate),
                "Primary key is re-legitimized");
    }

    /**
     * Keys with temporary validity.
     *
     * @see <a href="https://tests.sequoia-pgp.org/#Temporary_validity">Sequoia Test Suite</a>
     */
    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void testTemporaryValidity(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

        String keyA = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "Comment: D1A6 6E1A 23B1 82C9 980F  788C FBFC C82A 015E 7330\n" +
                "Comment: Bob Babbage <bob@openpgp.example>\n" +
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
                "bGU+wsFIBBMBCgB8BYJd73DyAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmc/vyRVu5eFsnOAwM7zvaPz1n/uAm2X7edm\n" +
                "veyqGs8EewMVCAoCmwICHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAepYMAInS\n" +
                "zYHHGoti6GJHJ3xB84JuO3obUo6f489uj4COdxACDuN9dHtRPe0AA2CATbXxwCQ7\n" +
                "waMorpXEXRDGtxvJPoHexK4xc1show7G/BBajPXXBlNgQztz/EOV18jKM6hsC5Bi\n" +
                "rw1JwHLmfkp2dvsT1RKVGTkVqDVU1ZLXhwnoSfVqT5ijSsRmmOjCFJen65WG5yii\n" +
                "PyGdcRF0AyL/j2dKaGxyRVO+SOIcNb1uNKSRt+heva3wmDWsnlzXv0KY4AXJPAuP\n" +
                "IsjHxknLHDm1KFi9C65hDz2cc8WYhTkM6wLc+JlxpZ2A9yft6CW1WxgcB3EDKFAz\n" +
                "uuynSAmxaBlVGrf2DfGzGC1HUy1bpXZbvHIG13bQPKoAGViQYbPabps4rBMpLv7Q\n" +
                "UV90eWw0DiJ6rdyQOwH63/DEsYOfY+OqitP5NPjXjgTqwHC26JAxPDFdfAV8iVFn\n" +
                "c2ubzxwJHY3NP75ifrUdGQUWVhaBGyZY8U46MQ28vhsXja5xVF1STG2HbPKJAsLB\n" +
                "TgQTAQoAggWCXaWc8gWDACTqAAILCQkQ+/zIKgFeczBHFAAAAAAAHgAgc2FsdEBu\n" +
                "b3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3JnECT1jL7Wh2YJV6JmGSDCEf1d9wRwDH/d\n" +
                "9s6tVNe2ENQDFQgKApsCAh4BFiEE0aZuGiOxgsmYD3iM+/zIKgFeczAAAAajDACZ\n" +
                "zqo3U2LN/NyzxK0RUuIRIJJn7kcUGCBPoKkdya/NcVn5jBiuwIqK/gSxWEpe+eI8\n" +
                "jpT+LbC1O3839oO0ntBy+u/Hz6PrNCUNDF18uexqtajIJpYHmk+61NozdCtoSMQJ\n" +
                "072Zvkod1/enc7OfR5VqyejFddcMUntmpTOHG+L50jPqHEU0+a8WOU7OZkkxYM/6\n" +
                "JqRTHaYcfZ4rbokRYfn6f2CuM6EGrdOpbsN9cmOmUU4qKQfQ6qY3BIxYM9oEyfCo\n" +
                "mzM98FwxbJVCfJP6sIUnusp1giikkWAlnyMxBSfL8qGpEiFOJZ/MtIYoCerr+lGY\n" +
                "uzA3ZIXI1tDCjb/UMRVmlbTYPvs6NyOKlwC/Hodz1cKBBv+5aY73K4NtNo6GBsvQ\n" +
                "ZNMWMc8VpqNH+i63XnUireWB+xjlCcX5vD2nnM+zy3K5dHobt+2+RD0+d3SEnyy9\n" +
                "G5hoe047lCmCffKF9QK/94v0UXCWGKfa5eM4Lvij6P+AXbnPvVAzjn/ltHrqCyQ=\n" +
                "=UNh9\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        String keyB = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "Comment: D1A6 6E1A 23B1 82C9 980F  788C FBFC C82A 015E 7330\n" +
                "Comment: Bob Babbage <bob@openpgp.example>\n" +
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
                "bGU+wsFYBDABCgCMBYJdyobyBYMAJOoACRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0\n" +
                "QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmc4DEsoTMy5GbMP55MVwbUsltFe21MM\n" +
                "wRCI1TeFXyEGohYdIFRlbXBvcmFyeSBzdXNwZW5zaW9uFiEE0aZuGiOxgsmYD3iM\n" +
                "+/zIKgFeczAAAIdaC/0ZrIywQx9YtCAT46xQJfQlg3qoXzocxdalzLce/z5weOU6\n" +
                "nBSntMTzA7i7kfjez61oTTqf4QUeN0ogkLrSVjtCRduN+jwqd1Q5UjMHWaw9iXso\n" +
                "I4BIhkwcgYS2mITHmgfpwfWoW/v0+YxHMO4xmBLJ112nXX85Kyy0+1fkF+QWspbA\n" +
                "rYXtxLVQr+tMC3lHjKCMcskTjRqpEPxA+DpEUjE5hs8moDFM5PqN3KRZMACqyprg\n" +
                "q+N7nsesAwUS8TbmQtkO4xYioVfPMiQavniyMG6B41oSmOJEHwnHt+mqvSCb0Q1n\n" +
                "HeyGuW4Woap81HBOypmwq4Lqwidv9y6gVkvWyvTdrsUQMKwIcR5JtISBlh3/6r20\n" +
                "NcyeE958hVh3s0DO+3t6IMSvcozMm6PhavlEoNY1lBbQpGeyo00wZDxs5VpmZaiX\n" +
                "NAcH3VbDdqvG+5qLPadUbmvzOKDEpMMaFhsucfhx0JOOlGo4csiucl+W/LmwrME9\n" +
                "kICKfqNo7CsxL1gR8Y7CwUgEEwEKAHwFgl2lnPICCwkJEPv8yCoBXnMwRxQAAAAA\n" +
                "AB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ4Xr6IvRQ7D8b0iCo5ME\n" +
                "1eYWvvk4TwkIy9LnnnbQDHo9AxUICgKbAgIeARYhBNGmbhojsYLJmA94jPv8yCoB\n" +
                "XnMwAABq/gv/ZzEDN3jJrP5V1OzCpdvvkhvmowYxGxdxuC5YQr4X4XYhZHsDZEQW\n" +
                "TInkXoth4xiLtNLqCvUEeNVMsm3fmChMUIWqEjLlCOVmR+VgUsn9kAns8jUVx05p\n" +
                "chwjbmmuJRL4UielITjaU8HF10yM7nx9j00fIoprIigA1IOg7tRTgWZnSu2c1BlP\n" +
                "0+gucz8SME3HzwUQETwHyuw/cwldsGxW35bIeQ+CM3ennqhSO4kD8KlL2ZIBQr/P\n" +
                "W52HBuiDQIIr79inzvYBDHm4Bv6tdkiTemRTobSK8QjCfG70DXSGly6sPJDgy662\n" +
                "e7IedgOYs3pLSTXvJgNpNNsjxn838ZMmXt9AMGwXo+PjtZhwyqA+hrkmt8rIFIF+\n" +
                "F5lhKO3q2fa8cPg+0u5pAUjw2x/aQj2Q6mVszPsLOdhJT2pi5KKXPuHDNTNKY4Ay\n" +
                "2ZV22uRw6W4B77OXyaOaDtvFj4Pw3Yh+e6JfV2zoATxUpzxhibxSkGdFgzNkJ3EW\n" +
                "iz7OblW3I9Dt\n" +
                "=qacX\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        String keyC = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "Comment: D1A6 6E1A 23B1 82C9 980F  788C FBFC C82A 015E 7330\n" +
                "Comment: Bob Babbage <bob@openpgp.example>\n" +
                "\n" +
                "xsDNBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
                "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
                "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
                "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
                "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
                "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
                "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
                "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
                "vLIwa3T4CyshfT0AEQEAAcLBWAQgAQoAjAWCXcqG8gWDACTqAAkQ+/zIKgFeczBH\n" +
                "FAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3JnAmmqXQGjUvL8\n" +
                "YLsbqoZEJMUrbs34XzSj8rWT7KAnbBIWHQNUZW1wb3Jhcnkgc3VzcGVuc2lvbhYh\n" +
                "BNGmbhojsYLJmA94jPv8yCoBXnMwAADNcgv8CQ4kAdzEqiz3+wITTKhm6Xer/7CC\n" +
                "ZOMV/POHRLaJkN5oOXxEkIzVZBV9Aj1TF12jUPtOnxbKqnaGtXYIOwcEXfKJXBQJ\n" +
                "Q3CqMFgeiodi42JOXSJaUHJbtQsb6CFghgj2e8RV5P35EKNAxa42QSl9/v4y6a0q\n" +
                "LtpzWS1OiLgfXxAXSMSeViuQgFkK/HB69u8OO8pN5h1rh9DmcNZTtwKJO7EUhmiD\n" +
                "L3bYsnhplci6XYre7glxw4Qg2ChyY4SRtWgdOJNKwZVXgE5lf+JCs+YFTANsHAeO\n" +
                "5iEEnGCBZp2ZFdPlcwnvCiMFUArnvKvHUS0lNj/SHv0WxtlgVgz8xCyciCjPbZFa\n" +
                "YtN1ejLl77S6sBfkwZ3cc7RgxBQlg0rTbrDcE+lejLL6oh9Dt093ndofVpjj5QSj\n" +
                "hq7C/WEby6Co5kZudZGx84OdFoGd6Pk8l7gZa3VR5aptR1q5c4Xfbs0phMSGaMLL\n" +
                "/gLYyLekz3Q4O/j/5I443A2NCIPeGYUBX6gvzSFCb2IgQmFiYmFnZSA8Ym9iQG9w\n" +
                "ZW5wZ3AuZXhhbXBsZT7CwUgEEwEKAHwFgl2lnPICCwkJEPv8yCoBXnMwRxQAAAAA\n" +
                "AB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ2Gj4Mbo1uUYOr7WMgMa\n" +
                "+TaZbFIDi89ViIuH5QjzHe+NAxUICgKbAgIeARYhBNGmbhojsYLJmA94jPv8yCoB\n" +
                "XnMwAAC4wwv/ZnAapaGGBQktIgq2JGAedKxwT/sf9yUEmpaNr79IfLvoDX+9A2WM\n" +
                "gqCCa/BaV0zDOS67Pd0AN37tMJ1LW9zHwSHax7UNNm+i0Zh4tWPWeYgftieipauq\n" +
                "cS8h40i6FoGkEFSnDX3PG3LrVxlRA2oj4iUg+sWvvOuKEfQ5wXIa0fc1Dkr4W2aC\n" +
                "7zzHa/SuJvVRWrl8RusWFci4wgF+YTgVMSn/144y+/3jSG7dx/M7VXzw2JMxbdkm\n" +
                "BpHvADcyPsrl+3yJcjVAL2tcqyCbDOpDf1Y2fuR0lPMs6ozni8ssZteX4MXZR1sY\n" +
                "n+ZqGxj5syT1TP4Yt09f2yKlBTudeMMiJQJhOokVDZxkLAXgW3Mq1+hS4EXhBGTl\n" +
                "EVyo+mwICjkHrIeIPs+0yvZy1dUaErIg93Frvc9DCqJcXSFXH8YRXDNodQxohMy7\n" +
                "higltKgq0PswBpnrHAGW+qPT+4l5zv37i2wgMt/9qpMUGOCmRW4Fzlv9GWJ2ODo+\n" +
                "916X5bFdC0Rr\n" +
                "=RTZe\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";

        String keyASigT0 = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsE7BAABCgBvBYJdkyfyCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmfAtB+VtWWsZc4DiK/QK7LEDG+KAl+ORwXnUahXErz3\n" +
                "GhYhBNGmbhojsYLJmA94jPv8yCoBXnMwAABlEAv/fe0No+TMQTq5xkyv2xNgzibB\n" +
                "sqeOBbmZL82PfGJTthEtZ+eKi0pNnGPlFH0VIkRskNRKEZqLGJh2d/xDstiPBTfc\n" +
                "TzTn66f43h+WnGRqGLYbKHfrJ+Mn/wHub9zxauDvpjcIqOLYscuZ+rvp/OyExoST\n" +
                "lOmfLsrpGgS//eMDchgeFTybZy3UP7dw+BHHSlMW/s4QvgqqS8v5x2bNgMcairzN\n" +
                "BMxafx6Mp4RSk46tF+INzPgV8W+ImyGXtkZcBmiv9/u36X6GESSyHl/DVf+ZlHm9\n" +
                "u35dGn8S2PhyE12eQnLZJoorqcIOtwx1sAD+317Dprv8fwcHBhgyKLVsx2O5NTWn\n" +
                "fZNRtdjQiUBt03D4Qdxoru/UzpGZWq4OLLZVB7u2B4tRQohkBCH96s5hvY2GHXSN\n" +
                "Md3FCvms+lCEFi70Ae1KZCpD1/DHCFQcT5fYMYVNU1HFB8eQoKMM3kmv0VpJ31CB\n" +
                "bJ0esmX6JDukiepzcr09w7bbkhGvKnDgUM3dNxhv\n" +
                "=PfHW\n" +
                "-----END PGP SIGNATURE-----\n";
        String keyASigT1_T2 = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsE7BAABCgBvBYJduBHyCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmcglTWhGNT4tUfWuGHHpZUQZGDvZ4AKjIM/B97lFgac\n" +
                "XBYhBNGmbhojsYLJmA94jPv8yCoBXnMwAADPmAv9EZlRAp65+JLsABQa8sk0YgRU\n" +
                "28n6/Wcv2nj0iZMtbnXu2hLJqPj62JihCNbElEgJb7NIYbTPEAiyUisq8sa+E12F\n" +
                "PvBsqcNAdLxlDRyPcwlDrbl0fRqLt/fiItMp6lHnfl2SfrSkzWv8t2DswPS+LXpt\n" +
                "k5GBWxnJMRQ2Lf1L8rriFY1p6D9XtO8n9wGWMzCoxp3q+diQa8YJbhppPPskU5rT\n" +
                "bPYH7f1FnU2OzzxgeqlAjtpjkTmzy3RNRlzGEYk6NnNbHQN0sQoiQdOaHMJ/qKMF\n" +
                "wanYX2iatYCCYJGMDv3Ysw6nXLyiZ6dbqFEJwzRCiZQ2ZBYvzRyEnMojIZE3CXOv\n" +
                "a+h5qm8Ffc+ZPc0spBoTxFCz8+Rmp5qNT9kFOIQUF9YOs/fo8sCr32ZbLu/bBsy9\n" +
                "RhswX42fnAZ4DZJKlAORbtYmM52WsPxArGLnpOpgD8aT4Mt7SsVpAJXnjn43NKTS\n" +
                "Qu+KulEt+Sn2/ioiQoKknxJWDkBZxHLkgRC3ejTO\n" +
                "=et/I\n" +
                "-----END PGP SIGNATURE-----\n";
        String keyASigT2_T3 = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsE7BAABCgBvBYJd3PvyCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmexsHg/HXrdneCOLkWkDj95sRwrSkFKyzFUJtY+9xLv\n" +
                "1RYhBNGmbhojsYLJmA94jPv8yCoBXnMwAAAqEQv+NdTRkL4vJA1Gst/LK7f3ytjF\n" +
                "H7kkMI9aTQVxnscsNMGZYBjzaT410if/axqCyAmJX3lPWfHIsIZWmglxEPK04K2b\n" +
                "Ql04JEpTzEVKIKGLBPhfLT/QamtZJmGpoGw7ba8lZ8Xrarb1Lf9srRBF+WKIzuwd\n" +
                "FQAGsPw/57Q4YXNwPnPJwQbOrfuZLLGGZLczGiBW8900NH0Rg82fcMdO2XmuXhMb\n" +
                "NnwYoXH7vV+i2uodfdmNhts9ENeiPmPF7DPiKDQtSQ6LLspVE/RoP/lXdd7cGSQR\n" +
                "J1IaWX1rN598wBz1wNVwBpxucxxIjm9JYER9+eV3oo08b0+DF4OppDcrJvGnQcdE\n" +
                "QuEOAqNeSrFGqXglfZ/Cep5ZkIVPtJA88e9FZYz7xlx49bh1os1jc7jeSA6xG/1O\n" +
                "48ZQiPrLkVZp/62j0GvFEZzOj0CVb+/J2gsQ32SYkKeiZfXIdodReQMYAiXHeEj2\n" +
                "mtuOFO8yVqWUwnlUwQoVAnr9zMulZB2Np29wvevU\n" +
                "=kusD\n" +
                "-----END PGP SIGNATURE-----\n";
        String keyASigT3_now = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsE7BAABCgBvBYJeAeXyCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmcElcHwXV0gKjafJ0j2dKF+EeukF5ywMBZMMkEyyjG4\n" +
                "jhYhBNGmbhojsYLJmA94jPv8yCoBXnMwAAASuAwAnu1KFMNci1CEkzJb5fkVZRGz\n" +
                "Cvo2wC0HXhwMoGm/icuw3qTNWpj3wCA6tOTgIGT6FwfYV42mNkFYpiUSelpIdTP7\n" +
                "R5wf7cvu2wS5sZo+q9a3K4T2gWu+hlLO00/q8LJYTAG3dQZd6Mhk3gPUh3qNWHuR\n" +
                "zi3gXajxaQ1yJrFHjRt86DBks5vCBWeFkcNQcuIZgoKlHsGxEgfQo0Yej6v4FBrQ\n" +
                "xr3iU4GhSAQOFmZQPL2AVOfE8if9CqNRNLGpkloEDAhoSf+TxRyWXFfvXZQGKgSA\n" +
                "oKbgQFyUgdybPFXiQa8ezZaO23risIG/7oe+rAM0vOWMA0f2F0d2W5t4UeZLLxsu\n" +
                "Gh+7ZYK/MDF1HgFHjYefoW7pSPoNzaSIFv6goCtTr1O2c7BnO9QxU1H1rWgkFUd0\n" +
                "NWHrk3H89te7fP94GtBskR1OnT8zxWVMtFx8NEDicrSw/sKqmxkxh0xW434ZtXgi\n" +
                "FT2kVzTaUKN+UQ7UIs9wgtqb+s7Dvb7b1bO8wvLg\n" +
                "=DeXH\n" +
                "-----END PGP SIGNATURE-----\n";
        String keyBSigT0 = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsE7BAABCgBvBYJdkyfyCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmfAtB+VtWWsZc4DiK/QK7LEDG+KAl+ORwXnUahXErz3\n" +
                "GhYhBNGmbhojsYLJmA94jPv8yCoBXnMwAABlEAv/fe0No+TMQTq5xkyv2xNgzibB\n" +
                "sqeOBbmZL82PfGJTthEtZ+eKi0pNnGPlFH0VIkRskNRKEZqLGJh2d/xDstiPBTfc\n" +
                "TzTn66f43h+WnGRqGLYbKHfrJ+Mn/wHub9zxauDvpjcIqOLYscuZ+rvp/OyExoST\n" +
                "lOmfLsrpGgS//eMDchgeFTybZy3UP7dw+BHHSlMW/s4QvgqqS8v5x2bNgMcairzN\n" +
                "BMxafx6Mp4RSk46tF+INzPgV8W+ImyGXtkZcBmiv9/u36X6GESSyHl/DVf+ZlHm9\n" +
                "u35dGn8S2PhyE12eQnLZJoorqcIOtwx1sAD+317Dprv8fwcHBhgyKLVsx2O5NTWn\n" +
                "fZNRtdjQiUBt03D4Qdxoru/UzpGZWq4OLLZVB7u2B4tRQohkBCH96s5hvY2GHXSN\n" +
                "Md3FCvms+lCEFi70Ae1KZCpD1/DHCFQcT5fYMYVNU1HFB8eQoKMM3kmv0VpJ31CB\n" +
                "bJ0esmX6JDukiepzcr09w7bbkhGvKnDgUM3dNxhv\n" +
                "=PfHW\n" +
                "-----END PGP SIGNATURE-----\n";
        String keyBSigT1_T2 = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsE7BAABCgBvBYJduBHyCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmcglTWhGNT4tUfWuGHHpZUQZGDvZ4AKjIM/B97lFgac\n" +
                "XBYhBNGmbhojsYLJmA94jPv8yCoBXnMwAADPmAv9EZlRAp65+JLsABQa8sk0YgRU\n" +
                "28n6/Wcv2nj0iZMtbnXu2hLJqPj62JihCNbElEgJb7NIYbTPEAiyUisq8sa+E12F\n" +
                "PvBsqcNAdLxlDRyPcwlDrbl0fRqLt/fiItMp6lHnfl2SfrSkzWv8t2DswPS+LXpt\n" +
                "k5GBWxnJMRQ2Lf1L8rriFY1p6D9XtO8n9wGWMzCoxp3q+diQa8YJbhppPPskU5rT\n" +
                "bPYH7f1FnU2OzzxgeqlAjtpjkTmzy3RNRlzGEYk6NnNbHQN0sQoiQdOaHMJ/qKMF\n" +
                "wanYX2iatYCCYJGMDv3Ysw6nXLyiZ6dbqFEJwzRCiZQ2ZBYvzRyEnMojIZE3CXOv\n" +
                "a+h5qm8Ffc+ZPc0spBoTxFCz8+Rmp5qNT9kFOIQUF9YOs/fo8sCr32ZbLu/bBsy9\n" +
                "RhswX42fnAZ4DZJKlAORbtYmM52WsPxArGLnpOpgD8aT4Mt7SsVpAJXnjn43NKTS\n" +
                "Qu+KulEt+Sn2/ioiQoKknxJWDkBZxHLkgRC3ejTO\n" +
                "=et/I\n" +
                "-----END PGP SIGNATURE-----\n";
        String keyBSigT2_T3 = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsE7BAABCgBvBYJd3PvyCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmexsHg/HXrdneCOLkWkDj95sRwrSkFKyzFUJtY+9xLv\n" +
                "1RYhBNGmbhojsYLJmA94jPv8yCoBXnMwAAAqEQv+NdTRkL4vJA1Gst/LK7f3ytjF\n" +
                "H7kkMI9aTQVxnscsNMGZYBjzaT410if/axqCyAmJX3lPWfHIsIZWmglxEPK04K2b\n" +
                "Ql04JEpTzEVKIKGLBPhfLT/QamtZJmGpoGw7ba8lZ8Xrarb1Lf9srRBF+WKIzuwd\n" +
                "FQAGsPw/57Q4YXNwPnPJwQbOrfuZLLGGZLczGiBW8900NH0Rg82fcMdO2XmuXhMb\n" +
                "NnwYoXH7vV+i2uodfdmNhts9ENeiPmPF7DPiKDQtSQ6LLspVE/RoP/lXdd7cGSQR\n" +
                "J1IaWX1rN598wBz1wNVwBpxucxxIjm9JYER9+eV3oo08b0+DF4OppDcrJvGnQcdE\n" +
                "QuEOAqNeSrFGqXglfZ/Cep5ZkIVPtJA88e9FZYz7xlx49bh1os1jc7jeSA6xG/1O\n" +
                "48ZQiPrLkVZp/62j0GvFEZzOj0CVb+/J2gsQ32SYkKeiZfXIdodReQMYAiXHeEj2\n" +
                "mtuOFO8yVqWUwnlUwQoVAnr9zMulZB2Np29wvevU\n" +
                "=kusD\n" +
                "-----END PGP SIGNATURE-----\n";
        String keyBSigT3_now = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsE7BAABCgBvBYJeAeXyCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmcElcHwXV0gKjafJ0j2dKF+EeukF5ywMBZMMkEyyjG4\n" +
                "jhYhBNGmbhojsYLJmA94jPv8yCoBXnMwAAASuAwAnu1KFMNci1CEkzJb5fkVZRGz\n" +
                "Cvo2wC0HXhwMoGm/icuw3qTNWpj3wCA6tOTgIGT6FwfYV42mNkFYpiUSelpIdTP7\n" +
                "R5wf7cvu2wS5sZo+q9a3K4T2gWu+hlLO00/q8LJYTAG3dQZd6Mhk3gPUh3qNWHuR\n" +
                "zi3gXajxaQ1yJrFHjRt86DBks5vCBWeFkcNQcuIZgoKlHsGxEgfQo0Yej6v4FBrQ\n" +
                "xr3iU4GhSAQOFmZQPL2AVOfE8if9CqNRNLGpkloEDAhoSf+TxRyWXFfvXZQGKgSA\n" +
                "oKbgQFyUgdybPFXiQa8ezZaO23risIG/7oe+rAM0vOWMA0f2F0d2W5t4UeZLLxsu\n" +
                "Gh+7ZYK/MDF1HgFHjYefoW7pSPoNzaSIFv6goCtTr1O2c7BnO9QxU1H1rWgkFUd0\n" +
                "NWHrk3H89te7fP94GtBskR1OnT8zxWVMtFx8NEDicrSw/sKqmxkxh0xW434ZtXgi\n" +
                "FT2kVzTaUKN+UQ7UIs9wgtqb+s7Dvb7b1bO8wvLg\n" +
                "=DeXH\n" +
                "-----END PGP SIGNATURE-----\n";
        String keyCSigT0 = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsE7BAABCgBvBYJdkyfyCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmfAtB+VtWWsZc4DiK/QK7LEDG+KAl+ORwXnUahXErz3\n" +
                "GhYhBNGmbhojsYLJmA94jPv8yCoBXnMwAABlEAv/fe0No+TMQTq5xkyv2xNgzibB\n" +
                "sqeOBbmZL82PfGJTthEtZ+eKi0pNnGPlFH0VIkRskNRKEZqLGJh2d/xDstiPBTfc\n" +
                "TzTn66f43h+WnGRqGLYbKHfrJ+Mn/wHub9zxauDvpjcIqOLYscuZ+rvp/OyExoST\n" +
                "lOmfLsrpGgS//eMDchgeFTybZy3UP7dw+BHHSlMW/s4QvgqqS8v5x2bNgMcairzN\n" +
                "BMxafx6Mp4RSk46tF+INzPgV8W+ImyGXtkZcBmiv9/u36X6GESSyHl/DVf+ZlHm9\n" +
                "u35dGn8S2PhyE12eQnLZJoorqcIOtwx1sAD+317Dprv8fwcHBhgyKLVsx2O5NTWn\n" +
                "fZNRtdjQiUBt03D4Qdxoru/UzpGZWq4OLLZVB7u2B4tRQohkBCH96s5hvY2GHXSN\n" +
                "Md3FCvms+lCEFi70Ae1KZCpD1/DHCFQcT5fYMYVNU1HFB8eQoKMM3kmv0VpJ31CB\n" +
                "bJ0esmX6JDukiepzcr09w7bbkhGvKnDgUM3dNxhv\n" +
                "=PfHW\n" +
                "-----END PGP SIGNATURE-----\n";
        String keyCSigT1_T2 = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsE7BAABCgBvBYJduBHyCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmcglTWhGNT4tUfWuGHHpZUQZGDvZ4AKjIM/B97lFgac\n" +
                "XBYhBNGmbhojsYLJmA94jPv8yCoBXnMwAADPmAv9EZlRAp65+JLsABQa8sk0YgRU\n" +
                "28n6/Wcv2nj0iZMtbnXu2hLJqPj62JihCNbElEgJb7NIYbTPEAiyUisq8sa+E12F\n" +
                "PvBsqcNAdLxlDRyPcwlDrbl0fRqLt/fiItMp6lHnfl2SfrSkzWv8t2DswPS+LXpt\n" +
                "k5GBWxnJMRQ2Lf1L8rriFY1p6D9XtO8n9wGWMzCoxp3q+diQa8YJbhppPPskU5rT\n" +
                "bPYH7f1FnU2OzzxgeqlAjtpjkTmzy3RNRlzGEYk6NnNbHQN0sQoiQdOaHMJ/qKMF\n" +
                "wanYX2iatYCCYJGMDv3Ysw6nXLyiZ6dbqFEJwzRCiZQ2ZBYvzRyEnMojIZE3CXOv\n" +
                "a+h5qm8Ffc+ZPc0spBoTxFCz8+Rmp5qNT9kFOIQUF9YOs/fo8sCr32ZbLu/bBsy9\n" +
                "RhswX42fnAZ4DZJKlAORbtYmM52WsPxArGLnpOpgD8aT4Mt7SsVpAJXnjn43NKTS\n" +
                "Qu+KulEt+Sn2/ioiQoKknxJWDkBZxHLkgRC3ejTO\n" +
                "=et/I\n" +
                "-----END PGP SIGNATURE-----\n";
        String keyCSigT2_T3 = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsE7BAABCgBvBYJd3PvyCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmexsHg/HXrdneCOLkWkDj95sRwrSkFKyzFUJtY+9xLv\n" +
                "1RYhBNGmbhojsYLJmA94jPv8yCoBXnMwAAAqEQv+NdTRkL4vJA1Gst/LK7f3ytjF\n" +
                "H7kkMI9aTQVxnscsNMGZYBjzaT410if/axqCyAmJX3lPWfHIsIZWmglxEPK04K2b\n" +
                "Ql04JEpTzEVKIKGLBPhfLT/QamtZJmGpoGw7ba8lZ8Xrarb1Lf9srRBF+WKIzuwd\n" +
                "FQAGsPw/57Q4YXNwPnPJwQbOrfuZLLGGZLczGiBW8900NH0Rg82fcMdO2XmuXhMb\n" +
                "NnwYoXH7vV+i2uodfdmNhts9ENeiPmPF7DPiKDQtSQ6LLspVE/RoP/lXdd7cGSQR\n" +
                "J1IaWX1rN598wBz1wNVwBpxucxxIjm9JYER9+eV3oo08b0+DF4OppDcrJvGnQcdE\n" +
                "QuEOAqNeSrFGqXglfZ/Cep5ZkIVPtJA88e9FZYz7xlx49bh1os1jc7jeSA6xG/1O\n" +
                "48ZQiPrLkVZp/62j0GvFEZzOj0CVb+/J2gsQ32SYkKeiZfXIdodReQMYAiXHeEj2\n" +
                "mtuOFO8yVqWUwnlUwQoVAnr9zMulZB2Np29wvevU\n" +
                "=kusD\n" +
                "-----END PGP SIGNATURE-----\n";
        String keyCSigT3_now = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsE7BAABCgBvBYJeAeXyCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmcElcHwXV0gKjafJ0j2dKF+EeukF5ywMBZMMkEyyjG4\n" +
                "jhYhBNGmbhojsYLJmA94jPv8yCoBXnMwAAASuAwAnu1KFMNci1CEkzJb5fkVZRGz\n" +
                "Cvo2wC0HXhwMoGm/icuw3qTNWpj3wCA6tOTgIGT6FwfYV42mNkFYpiUSelpIdTP7\n" +
                "R5wf7cvu2wS5sZo+q9a3K4T2gWu+hlLO00/q8LJYTAG3dQZd6Mhk3gPUh3qNWHuR\n" +
                "zi3gXajxaQ1yJrFHjRt86DBks5vCBWeFkcNQcuIZgoKlHsGxEgfQo0Yej6v4FBrQ\n" +
                "xr3iU4GhSAQOFmZQPL2AVOfE8if9CqNRNLGpkloEDAhoSf+TxRyWXFfvXZQGKgSA\n" +
                "oKbgQFyUgdybPFXiQa8ezZaO23risIG/7oe+rAM0vOWMA0f2F0d2W5t4UeZLLxsu\n" +
                "Gh+7ZYK/MDF1HgFHjYefoW7pSPoNzaSIFv6goCtTr1O2c7BnO9QxU1H1rWgkFUd0\n" +
                "NWHrk3H89te7fP94GtBskR1OnT8zxWVMtFx8NEDicrSw/sKqmxkxh0xW434ZtXgi\n" +
                "FT2kVzTaUKN+UQ7UIs9wgtqb+s7Dvb7b1bO8wvLg\n" +
                "=DeXH\n" +
                "-----END PGP SIGNATURE-----\n";

        PGPPublicKeyRing keysA = PGPainless.readKeyRing().publicKeyRing(keyA);
        PGPPublicKeyRing keysB = PGPainless.readKeyRing().publicKeyRing(keyB);
        PGPPublicKeyRing keysC = PGPainless.readKeyRing().publicKeyRing(keyC);

        PGPSignature sigAT0 = SignatureUtils.readSignatures(keyASigT0).get(0);
        PGPSignature sigAT1_T2 = SignatureUtils.readSignatures(keyASigT1_T2).get(0);
        PGPSignature sigAT2_T3 = SignatureUtils.readSignatures(keyASigT2_T3).get(0);
        PGPSignature sigAT3_now = SignatureUtils.readSignatures(keyASigT3_now).get(0);
        PGPSignature sigBT0 = SignatureUtils.readSignatures(keyBSigT0).get(0);
        PGPSignature sigBT1_T2 = SignatureUtils.readSignatures(keyBSigT1_T2).get(0);
        PGPSignature sigBT2_T3 = SignatureUtils.readSignatures(keyBSigT2_T3).get(0);
        PGPSignature sigBT3_now = SignatureUtils.readSignatures(keyBSigT3_now).get(0);
        PGPSignature sigCT0 = SignatureUtils.readSignatures(keyCSigT0).get(0);
        PGPSignature sigCT1_T2 = SignatureUtils.readSignatures(keyCSigT1_T2).get(0);
        PGPSignature sigCT2_T3 = SignatureUtils.readSignatures(keyCSigT2_T3).get(0);
        PGPSignature sigCT3_now = SignatureUtils.readSignatures(keyCSigT3_now).get(0);

        Policy policy = PGPainless.getPolicy();
        Date validationDate = new Date();
        String data = "Hello World :)";

        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                sigAT0, getSignedData(data), keysA, policy, validationDate),
                "Signature predates key creation time");
        assertDoesNotThrow(() -> SignatureChainValidator.validateSignatureChain(
                sigAT1_T2, getSignedData(data), keysA, policy, validationDate),
                "Key valid");
        assertThrows(SignatureValidationException.class, () ->
                        SignatureChainValidator.validateSignatureChain(
                                sigAT2_T3, getSignedData(data), keysA, policy, validationDate),
                "Key is not valid, as subkey binding expired");
        assertDoesNotThrow(() -> SignatureChainValidator.validateSignatureChain(
                sigAT3_now, getSignedData(data), keysA, policy, validationDate),
                "Key is valid again");

        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                sigBT0, getSignedData(data), keysB, policy, validationDate),
                "Signature predates key creation time");
        assertDoesNotThrow(() -> SignatureChainValidator.validateSignatureChain(
                sigBT1_T2, getSignedData(data), keysB, policy, validationDate),
                "Key is valid");
        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                sigBT2_T3, getSignedData(data), keysB, policy, validationDate),
                "Primary key is not signing-capable");
        assertDoesNotThrow(() -> SignatureChainValidator.validateSignatureChain(
                sigBT3_now, getSignedData(data), keysB, policy, validationDate),
                "Key is valid again");

        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                sigCT0, getSignedData(data), keysC, policy, validationDate),
                "Signature predates key creation time");
        assertDoesNotThrow(() -> SignatureChainValidator.validateSignatureChain(
                sigCT1_T2, getSignedData(data), keysC, policy, validationDate),
                "Key is valid");
        assertThrows(SignatureValidationException.class, () -> SignatureChainValidator.validateSignatureChain(
                sigCT2_T3, getSignedData(data), keysC, policy, validationDate),
                "Key is revoked");
        assertDoesNotThrow(() -> SignatureChainValidator.validateSignatureChain(
                sigCT3_now, getSignedData(data), keysC, policy, validationDate),
                "Key is valid again");
    }

    private static InputStream getSignedData(String data) {
        return new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void testNoIssuer() throws IOException, PGPException {
        String SIG = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsExBAABCABlBYJhBZl3RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEt\n" +
                "cGdwLm9yZ6u++H3Om9Z3+mn7nyt3TSxs4o/D4fHi+e+X+/7jEj3dFiEE0aZuGiOx\n" +
                "gsmYD3iM+/zIKgFeczAAAOQKDACD4krXC/9GQQcl+waBglgmQaUWd+YEpXlPDQc3\n" +
                "dPF7kkc/pRmmGVur8kk8rWmuQwNvQt7vGD2YJzcWBFvSSZlbYa89Gd3L5H2keTYC\n" +
                "0Q/VbZqBp9ONtK3D9Yrti2jMYdcb30LZQnsSUsB0mwX41AxjPLx0FAcVMAEADjq/\n" +
                "zLkJ1y+vXCko653qS/um6VQGK8JeNHRz8ghrc4k0E2yYadWWO07wxuoTAlwskf32\n" +
                "MdSVeIUQIEZqEgWMbqtqglqL3eNWk56IonCePtulkQSN6qi4JpqTeudlOm+Zp/IN\n" +
                "Tk+vrdS8PyQ0CiM794t/iHZDK5Jyz4ccFhTLPbF58xnwkwqdWPdf8WjCzaLfZcuN\n" +
                "zajVdDXOBjNC1s10voENZhChsZYc9BfHqVMrOe8ngLKCCzqlJ/E930OJiZX5pc+H\n" +
                "mHaHdn0m6lrhM5JX6RT9TNS/yrjdpkScb68Rcf+rXdeSoCE/aDOCVXhIhVTMQ9di\n" +
                "Ch80fhwtYYjAM9G0/AEs7uBCGQQ=\n" +
                "=NDO/\n" +
                "-----END PGP SIGNATURE-----\n";

        String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
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
        String DATA = "Hello World :)";

        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(DATA.getBytes(StandardCharsets.UTF_8)))
                .withOptions(new ConsumerOptions()
                        .addVerificationCert(PGPainless.readKeyRing().publicKeyRing(CERT))
                        .addVerificationOfDetachedSignatures(new ByteArrayInputStream(SIG.getBytes(StandardCharsets.UTF_8))));

        Streams.drain(decryptionStream);

        decryptionStream.close();
        OpenPgpMetadata metadata = decryptionStream.getResult();

        assertFalse(metadata.getVerifiedSignatures().isEmpty());
    }
}
