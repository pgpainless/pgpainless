// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.pgpainless.PGPainless;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.signature.consumer.CertificateValidator;
import org.pgpainless.util.TestImplementationFactoryProvider;

public class KeyRevocationTest {

    private static final String data = "Hello, World";

    @ParameterizedTest
    @ArgumentsSource(TestImplementationFactoryProvider.class)
    public void subkeySignsPrimaryKeyRevokedNoReason(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

        String key = "-----BEGIN PGP ARMORED FILE-----\n" +
                "Comment: ASCII Armor added by openpgp-interoperability-test-suite\n" +
                "\n" +
                "xsBNBFpJegABCAC1ePFquP0135m8DYhcybhv7l+ecojitFOd/jRM7hCczIqKgalD\n" +
                "1Ro1gNr3VmH6FjRIKIvGT+sOzCKne1v3KyAAPoxtwxjkATTKdOGo15I6v5ZjmO1d\n" +
                "rLQOLSt1TF7XbQSt+ns6PUZWJL907DvECUU5b9FkNUqfQ14QqY+gi7MOyAQez3b7\n" +
                "Pg5Cyz/kVWQ6TSMW/myDEDEertQ4rDBsptEDFHCC2+iF4hO2LqfiCriu5qyLcKCQ\n" +
                "pd6dEuwJQ/jjT0D9A9Fwf+i04x6ZPKSU9oNAWqn8OSAq3/0B/hu9V+0U0iHPnJxe\n" +
                "quykvJk7maxhiGhxBWYXTvDJmoon0NOles7LABEBAAHCwHMEIAEKAAYFglwqrYAA\n" +
                "IQkQaE+tYtwDj7sWIQTy0VCk/piSXVHpFTloT61i3AOPu9wIB/sEXov0SN63jhHX\n" +
                "aVQWVWukecit/9BYQHpxRcHC6cBdxfw8peGXXyRnr0hJn9USKDH87KvmLHbjGUMd\n" +
                "aILnSc6klWtuB5HTu2S6LppUnQHUciavSZUc1P1A0BbmXoMyI0zNna1UP/n3kPgP\n" +
                "YT7yTpLROkTY2us10s59cuYWVXzQT4MfEGQVZ/2YBXErGKhafkCDHe1XPhEpJ8/K\n" +
                "mXhk3gQjflm43E7hhZuo/Qo2lCU8XCOibe08J0zPsOTY3fwFV2Vqyq9HS39YYMhj\n" +
                "QJfxxICJjAtzE8v+ze3QWzTEWxqLbNKeQ1FXuYW7wMQv8HHoJTgfnIcn1Lsihlvl\n" +
                "ph4T7B+jwsB8BB8BCgAPBYJeC+EAAhUKApsDAh4BACEJEGhPrWLcA4+7FiEE8tFQ\n" +
                "pP6Ykl1R6RU5aE+tYtwDj7vH3wf/UOtHYOtKoQNqz53f9XQi9gfnPEVp6uOD6Yox\n" +
                "N4ANUUL3EUBOYzczEqPzJxtJki+cB3k7I0nfw0SN5xz9Oq7OkLm9dTaCoTbsmt5m\n" +
                "s/YMs3mTHP4zYm/N/wcxQq8bEkJvvVh7q8V3llzjzC2bN8Uv4xtBA7QidhZuFBdf\n" +
                "X3CMncDf7LBeDRqXwmPNvsE0seI6CN3ESjmwhSWmgYBuZ5fnha+3H4xCLqgiQmkL\n" +
                "F4qgXu3eldyqjdfLfgoEmsmzGV3MrEP1EsRJC4SAdqTmcHM+BN00xYMUQMXK+HLO\n" +
                "AXdj0c92eRSk86NJmvxbdFHxSUfnwnLOefp+pAvStMvxOwWNocLAfAQfAQoADwWC\n" +
                "Wkl6AAIVCgKbAwIeAQAhCRBoT61i3AOPuxYhBPLRUKT+mJJdUekVOWhPrWLcA4+7\n" +
                "qg0H+wakw+hjU8Fzzrf9JB0D2Jm3SLV/qVj/qN42gelUxw13J9u27bQOTPNhF2X2\n" +
                "nuPmwtXTAftbi2peHIlYDvSJiQvTcLOX3NyR+Eebrkr6Y847nZCbBrt3AChN4cIk\n" +
                "/dzIurehDaSwg0sascwJn6DkG1SWFmO4D+2eAo9CAD9vWqaxHNCVqDIxyqSoGBer\n" +
                "tLFoB1gbhF5P+qOhmG9h2WCuMnKWNllyoFYcu/4kA2DtRTn3FkFx1Ri5/DsyC46G\n" +
                "yqITXp009tGYQAEoty1A0gzE0H8UklbdJ4c1rlySeEfD81FXkSdANKDMo2VR4rxw\n" +
                "uhsDLIkLklE8fHvxpzgcjqnxp3vNEmp1bGlldEBleGFtcGxlLm9yZ8LAcwQTAQoA\n" +
                "BgWCWkl6AAAhCRBoT61i3AOPuxYhBPLRUKT+mJJdUekVOWhPrWLcA4+7Q30H/j58\n" +
                "bCBbv9I7igVI47QGH0c5K62LTHqT47Wk7xn6NUs1JF/+hfxo3UnlYOSKumHAa4/H\n" +
                "PnAdxKGaR50nE4FkB8HHlkC3fR4W4E61Db1tXoNglczdEQbmDLVrvSTOKR+7LCVt\n" +
                "TZjfvzfQeu6m9sviXwcB/5WudPDcwq5d8Vk8Y0+cDcvhRpDWYNt7P9KpTtrsQo3P\n" +
                "pkQLgJaeRJkzlVjiAWzNMbbYwTsd/WZllkCiWdJ6xYytY6aR6ms8FljV+0R5CvNb\n" +
                "ZW0lLTj6EyCQ89/DWosjHGR96faJDdw1OF7RfqBNfDPmfxNMVEJrpm5Goxc3FI5n\n" +
                "e3p6Mz+QZxhEs3TUuV3OwE0EWkrLgAEIAMpG/LapVl7ahxhpAagKtxJ6Zrwaqyr6\n" +
                "no47WSgF6hLMyfTZYmwhlLi8JzTlTkf4XDlJThh/nMjHAKQViQfu3f/NytXggnb/\n" +
                "PJwxVWr+4SiypRAW2STR4B6Sd9d6ZXrcwkeMd0kxCEqxLTu9ZdhwXaykmF2sRoCC\n" +
                "8WMHEot4thI88UQ8vtM8svLO3fjg+UoRWHsYEqyh918dXMUACcxhiVce+Rx1PRlY\n" +
                "d8R8Ce5w5tuisx3oBtlzyAVyds/L5rElU1so9AI0+JFVWqTdH/OACio8kO34Lgs1\n" +
                "xhxVfY5sQ8fmB/vR4YyKx0s2w8evuMMkbMY+0rvobv26ICdvJ52080MAEQEAAcLB\n" +
                "rAQYAQoACQWCXgvhAAKbAgFXCRBoT61i3AOPu8B0oAQZAQoABgWCXgvhAAAhCRBK\n" +
                "cjSjoSE6ZRYhBFF5LA5I4v2pTpO5EUpyNKOhITplp0kIAIrv83RJh3+lm8H27P3O\n" +
                "hTm3z8Rrsy5EK+H2SnKivNTLUdZodVlSyUYF1uLvHB7Wch+aU4Z4DHFIss1rGtIO\n" +
                "iWs/MOrK/1r93tanUwiE7JDK1gg2qA4Q9rXgI5lrpPbvGQTye8YZnvkP1EPdMaJk\n" +
                "PzXQiWn4q5Ng7Pdqeze0SkhEtSssAYXzjSWz8NU3WfTLbPgxo5LnGG3vmcz8ay6V\n" +
                "l7q9QUhhKgbUwBlt3Uv8acAWDZYWrFx42DK+B3iGGGDsfqEeSYA2KFX6dpNA8Cv0\n" +
                "F6IG42vv1Y7/i613TWNLdWwN+RTZ5et+zPIgja17yKERQEWzcoHvHP40lhjywf7S\n" +
                "MjYWIQTy0VCk/piSXVHpFTloT61i3AOPuxS8CACtRp4DTJ67sVjOBKIISk0pija3\n" +
                "eqf3d1rHfsttNfQOzc/uDsnZBA75jVVYZVHH4Dn9i+gX+t8HTdIaPjg4QrjUqh3u\n" +
                "jS9TYXSE2zBpw3Sm+eyCAfQriRaSC5/S2dRIuiTxKZqYkhGi/lSbdXzJ33PI7RfD\n" +
                "d1nEVXybKtWrJV3vDaYO9PWFYJtjl7DVoJLZfX3IruBDU8m0Bo6TfVk2tWlNZ5JK\n" +
                "OjVKCH47TPjzuFVO8dNDPnUybGBoZ3PehLU/BH0gCBQSmUQJDARYRHHZMWvIQiiN\n" +
                "/p8iN4E6tE3BUk98MtOQJqFe8JYM1ADLFuzFdjaRu3ybpdkO6bisPrnQVHNEwsGs\n" +
                "BBgBCgAJBYJa6P+AApsCAVcJEGhPrWLcA4+7wHSgBBkBCgAGBYJa6P+AACEJEEpy\n" +
                "NKOhITplFiEEUXksDkji/alOk7kRSnI0o6EhOmXhRwf/do4VE16xIIaOg2IZlRbl\n" +
                "2tzRoQIyMmaN8mBzKC/Wmdw1Mo8YQMkQ6SNgq2oUOCbD4Xo9pvt3x1mt+P7W+ZqR\n" +
                "2BVhGoUL3VkhQnFO6djVCnKtszQOosTtvn0EIZm62EfkxcWJoS4whlDbdeBP12iC\n" +
                "9VcT0DgOSm4kT6WvAbFDZTYpPQEj1sp9GQNK4ydWVe5yWq11W7mQxHFA7g5t3AOb\n" +
                "bqe47gfH089gQ3INymvjnDxM9BoGX6vSuNHYt6/SBywYTTx4nhVSI/Y/ycjJ071T\n" +
                "nHjNyf0W9DAliVW1zQSqUTA4mwkIfu326skBDP8yKZpNE4AaU2WajD9IMWHViJk9\n" +
                "SBYhBPLRUKT+mJJdUekVOWhPrWLcA4+7TrYIAIYAKrzgdeNi9kpEt2SHcLoQLViz\n" +
                "xwrRMATqhrT/GdtOK6gJm5ycps6O+/jk/kknJw068MzlCZwotKj1MX7sYbx8ZwcQ\n" +
                "SI2qDHBfvoirKhdb3+lrlzo2ydTfCNPKQdp4obeTMSGfazBg3gEo+/V+yPSY87Hd\n" +
                "9DlRn02cst1cmD8XCep/7GaHDZmk79PxfCt04q0h+iQ13WOc4q0YvfRid0fgC+js\n" +
                "8awobryxUhLSESa1uV1X4N8IXNFw/uSfUbB6C997m/WYUBxSrI639JxmGxBcDIUn\n" +
                "crH02GDG8CotAnEHkLTz9GPO80q8mowzBV0EtHsXb4TeAFw5T5Qd0a5I+wk=\n" +
                "=2oji\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sigT0 = "-----BEGIN PGP ARMORED FILE-----\n" +
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
        String sigT1T2 = "-----BEGIN PGP ARMORED FILE-----\n" +
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
        String sigT2T3 = "-----BEGIN PGP ARMORED FILE-----\n" +
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
        String sigT3Now = "-----BEGIN PGP ARMORED FILE-----\n" +
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
        PGPSignature t0 = SignatureUtils.readSignatures(sigT0).get(0);
        PGPSignature t1t2 = SignatureUtils.readSignatures(sigT1T2).get(0);
        PGPSignature t2t3 = SignatureUtils.readSignatures(sigT2T3).get(0);
        PGPSignature t3now = SignatureUtils.readSignatures(sigT3Now).get(0);

        assertThrows(SignatureValidationException.class, () -> CertificateValidator.validateCertificateAndVerifyUninitializedSignature(t0,
                new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)),
                publicKeys, PGPainless.getPolicy(), new Date()));
        assertThrows(SignatureValidationException.class, () -> CertificateValidator.validateCertificateAndVerifyUninitializedSignature(t1t2,
                new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)),
                publicKeys, PGPainless.getPolicy(), new Date()));
        assertThrows(SignatureValidationException.class, () -> CertificateValidator.validateCertificateAndVerifyUninitializedSignature(t2t3,
                new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)),
                publicKeys, PGPainless.getPolicy(), new Date()));
        assertThrows(SignatureValidationException.class, () -> CertificateValidator.validateCertificateAndVerifyUninitializedSignature(t3now,
                new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)),
                publicKeys, PGPainless.getPolicy(), new Date()));
    }

    /**
     * Test signature verification with an evolving signing subkey.
     *
     * @see <a href="https://tests.sequoia-pgp.org/#Key_revocation_test__subkey_signs__primary_key_is_not_revoked__base_case_">Sequoia Test-Suite</a>
     */
    @ParameterizedTest
    @ArgumentsSource(TestImplementationFactoryProvider.class)
    public void subkeySignsPrimaryKeyNotRevoked(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

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
                "wyRsxj7Su+hu/bogJ28nnbTzQwARAQABwsGsBBgBCgAJBYJeC+EAApsCAVcJEGhP\n" +
                "rWLcA4+7wHSgBBkBCgAGBYJeC+EAACEJEEpyNKOhITplFiEEUXksDkji/alOk7kR\n" +
                "SnI0o6EhOmWnSQgAiu/zdEmHf6Wbwfbs/c6FObfPxGuzLkQr4fZKcqK81MtR1mh1\n" +
                "WVLJRgXW4u8cHtZyH5pThngMcUiyzWsa0g6Jaz8w6sr/Wv3e1qdTCITskMrWCDao\n" +
                "DhD2teAjmWuk9u8ZBPJ7xhme+Q/UQ90xomQ/NdCJafirk2Ds92p7N7RKSES1KywB\n" +
                "hfONJbPw1TdZ9Mts+DGjkucYbe+ZzPxrLpWXur1BSGEqBtTAGW3dS/xpwBYNlhas\n" +
                "XHjYMr4HeIYYYOx+oR5JgDYoVfp2k0DwK/QXogbja+/Vjv+LrXdNY0t1bA35FNnl\n" +
                "637M8iCNrXvIoRFARbNyge8c/jSWGPLB/tIyNhYhBPLRUKT+mJJdUekVOWhPrWLc\n" +
                "A4+7FLwIAK1GngNMnruxWM4EoghKTSmKNrd6p/d3Wsd+y2019A7Nz+4OydkEDvmN\n" +
                "VVhlUcfgOf2L6Bf63wdN0ho+ODhCuNSqHe6NL1NhdITbMGnDdKb57IIB9CuJFpIL\n" +
                "n9LZ1Ei6JPEpmpiSEaL+VJt1fMnfc8jtF8N3WcRVfJsq1aslXe8Npg709YVgm2OX\n" +
                "sNWgktl9fciu4ENTybQGjpN9WTa1aU1nkko6NUoIfjtM+PO4VU7x00M+dTJsYGhn\n" +
                "c96EtT8EfSAIFBKZRAkMBFhEcdkxa8hCKI3+nyI3gTq0TcFST3wy05AmoV7wlgzU\n" +
                "AMsW7MV2NpG7fJul2Q7puKw+udBUc0TCwawEGAEKAAkFglro/4ACmwIBVwkQaE+t\n" +
                "YtwDj7vAdKAEGQEKAAYFglro/4AAIQkQSnI0o6EhOmUWIQRReSwOSOL9qU6TuRFK\n" +
                "cjSjoSE6ZeFHB/92jhUTXrEgho6DYhmVFuXa3NGhAjIyZo3yYHMoL9aZ3DUyjxhA\n" +
                "yRDpI2CrahQ4JsPhej2m+3fHWa34/tb5mpHYFWEahQvdWSFCcU7p2NUKcq2zNA6i\n" +
                "xO2+fQQhmbrYR+TFxYmhLjCGUNt14E/XaIL1VxPQOA5KbiRPpa8BsUNlNik9ASPW\n" +
                "yn0ZA0rjJ1ZV7nJarXVbuZDEcUDuDm3cA5tup7juB8fTz2BDcg3Ka+OcPEz0GgZf\n" +
                "q9K40di3r9IHLBhNPHieFVIj9j/JyMnTvVOceM3J/Rb0MCWJVbXNBKpRMDibCQh+\n" +
                "7fbqyQEM/zIpmk0TgBpTZZqMP0gxYdWImT1IFiEE8tFQpP6Ykl1R6RU5aE+tYtwD\n" +
                "j7tOtggAhgAqvOB142L2SkS3ZIdwuhAtWLPHCtEwBOqGtP8Z204rqAmbnJymzo77\n" +
                "+OT+SScnDTrwzOUJnCi0qPUxfuxhvHxnBxBIjaoMcF++iKsqF1vf6WuXOjbJ1N8I\n" +
                "08pB2niht5MxIZ9rMGDeASj79X7I9Jjzsd30OVGfTZyy3VyYPxcJ6n/sZocNmaTv\n" +
                "0/F8K3TirSH6JDXdY5zirRi99GJ3R+AL6OzxrChuvLFSEtIRJrW5XVfg3whc0XD+\n" +
                "5J9RsHoL33ub9ZhQHFKsjrf0nGYbEFwMhSdysfTYYMbwKi0CcQeQtPP0Y87zSrya\n" +
                "jDMFXQS0exdvhN4AXDlPlB3Rrkj7CQ==\n" +
                "=+VTZ\n" +
                "-----END PGP ARMORED FILE-----\n";
        String sig = "-----BEGIN PGP ARMORED FILE-----\n" +
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

        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(key);
        PGPSignature signature = SignatureUtils.readSignatures(sig).get(0);

        CertificateValidator.validateCertificateAndVerifyUninitializedSignature(signature,
                new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)),
                publicKeys, PGPainless.getPolicy(), new Date());
    }
}
