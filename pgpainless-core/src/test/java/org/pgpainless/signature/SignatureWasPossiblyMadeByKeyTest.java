// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.signature.consumer.SignatureValidator;

public class SignatureWasPossiblyMadeByKeyTest {

    public static PGPPublicKeyRing CERT;
    public static PGPPublicKey SIGKEY;
    public static PGPPublicKey NOSIGKEY;
    static {
        try {
            CERT = PGPainless.readKeyRing().publicKeyRing("-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
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
                    "-----END PGP PUBLIC KEY BLOCK-----\n");
            SIGKEY = CERT.getPublicKey(new OpenPgpV4Fingerprint("D1A66E1A23B182C9980F788CFBFCC82A015E7330").getKeyId());
            NOSIGKEY = CERT.getPublicKey(new OpenPgpV4Fingerprint("1DDCE15F09217CEE2F3B37607C2FAA4DF93C37B2").getKeyId());
        } catch (IOException e) {
            fail("Cannot parse certificate");
        }
    }

    @Test
    public void issuer() throws PGPException {
        String sigWithIssuer = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsE7BAABCABlBYJgyf21RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEt\n" +
                "cGdwLm9yZ41vMHyr0Q9WbEh89cDcZt1LU9wR1Li+3wXFW0I0Lv4qFiEE0aZuGiOx\n" +
                "gsmYD3iM+/zIKgFeczAACgkQ+/zIKgFeczCN/Av+P/RqTj8hMDTsoQWggQS3EPmx\n" +
                "5u43yp8JCNuIKiDwTy+civQpAsfWLKhwmHZqokPonMtVSvxH9RFry9x8MpaaQzag\n" +
                "gNO2XwsFFpYa3ce/vjOHv+b9JGfPsSak6RvcPKV99AjqAnxDj93Q9od5DzmWo4jp\n" +
                "i9zt1Kj1AGEgqg/tp9jmmIEJ6ZgjM1sAysyE2YFU0hc0xySKI8+pBk8YG3fj8Twq\n" +
                "d6FDQ3CTvpApdrL5EKW3qW1K/vBvmck15GZOxAsiXaPoiIPDJPxBCy0koK7z/Z+0\n" +
                "vCft+isreOB9B1b68iGdaET9W+bd0ODdZHTfi7KmtG1D8+Ep4oVL8IRuWmf2M1Z9\n" +
                "qI93KxIYqanw0I5HDsfd/5IQ4X1ZD5hoMy+ICLKHQirQzyXL1tjYcw6NPJt0jAHR\n" +
                "LNlerP+KD288SPzu7jymsRXfxp91F1n+UT8n7kG16YARBGhc7hen858EJXn9dtWi\n" +
                "cqP71SMuOwD+JNuWQCd4e1WaTWNXrB1xerzmuWFc\n" +
                "=4ZFC\n" +
                "-----END PGP SIGNATURE-----";
        assertWasPossiblyMadeByKey(SIGKEY, get(sigWithIssuer));
    }

    @Test
    public void hashedIssuer() throws PGPException {
        String sigWithHashedIssuer = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsE7BAABCABvBYJgyf21CRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
                "cy5zZXF1b2lhLXBncC5vcmcQXJVlUI2e8ug0H1ekty9QUCLzgzv/H/U243WfBpJP\n" +
                "PBYhBNGmbhojsYLJmA94jPv8yCoBXnMwAADK5Av/XIuS13XrduVk3V7a28Uz9ARz\n" +
                "l2eHgOuSyM8IovCaWvO+L8KaCsFXVYUB0cHEHzH0QfyMapkVymsjLmqT5ULdwdKf\n" +
                "HsPluhZQlgEzeS043/uoikBgGOF+u0hdsibVpW0TVp0vZgBpuD7raLQQ9eWymRUE\n" +
                "dZ1dwWPc5OD3OV6jVwjNPoLy8yQaYLhfRser/h+pIFTL8XSqjPMDklN+oLnzZkvo\n" +
                "A0OCupqpiDtrREmeTVKDkL0DJ0DM7qMky7oI1qB4i3Ryt7gMUzpy7nK6APosi5Rg\n" +
                "vPuofxHle32pzaMDbBFQFcFYsXFdzmQdCcIx1myo6yrdkq4RMYXR20+cE+4R0pcQ\n" +
                "JZhDFyx3d/7vloWXeXM9HT+asPVfub+HXPFkqvsFulogpo/Pr66Og6+fRc2FPPSO\n" +
                "HmamWg1mMpzca8F35zZie1ICT7Qdef+aBcUb/7gwlv0Fd4FYWaIcleve4YtEacE/\n" +
                "Q0Quxar3DOTtNNQVrXeoeIlVGue0pNCwg6abDj5N\n" +
                "=IcX1\n" +
                "-----END PGP SIGNATURE-----\n";
        assertWasPossiblyMadeByKey(SIGKEY, get(sigWithHashedIssuer));
    }

    @Test
    public void noIssuerNoFingerprint() throws PGPException {
        String sigWithNoIssuerNoFingerprint = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsEaBAABCABOBYJgyf21RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEt\n" +
                "cGdwLm9yZ2T4siBf1CQ8wqT+oTCmxVm6OC+KC/kvqQdQ4AAGC68JAAC3Zwv/d70q\n" +
                "hUeTJrMXGej1/FkNOSKyjVRnJusDEojc4eQ/+Ov8jdByj2Rcr44UH7ZICtWuR4gc\n" +
                "ZrG9+DBFKgeuY6TawyBbTj3NU4IEOqihtn8RDBEXKIc91cW9BuqLyxvoUr432g6y\n" +
                "7l7nyXf17kPx8E62BjOhUz0NuwRQ5c2pnIRDe37xX0519DMf9PaywTAgs4eZaKXd\n" +
                "e1JLYvkd7BuMaT17VEggdRLM3GJGAJfZQ4+eoOmAzGRs1xGZrvcs2AH+OOzslU5l\n" +
                "t2nR9N7BCLX0NZVIP5KpRzw/puIFBiFj7zrPb7CJqKb0UEK8qngukASlvzYZTjHA\n" +
                "03qAeYqUj6LXTPNYlobPsGB0Srt2j7ycpeOYh6c3l7pKkvyaQL4QVawECMxsymu0\n" +
                "iMrLtyuWclsBcRDezIHQqKHOhSeCLt67SJj2+fCa+7WgQdvBT//3McFVsWnLQJsq\n" +
                "zVflI4b3E2kyhRgYK7f6jaa0OZ7BJRpQ3RRNk0Oq3rIYjysrwkbBG9N6tnCk\n" +
                "=NdKQ\n" +
                "-----END PGP SIGNATURE-----";


        assertWasPossiblyMadeByKey(SIGKEY, get(sigWithNoIssuerNoFingerprint));
    }

    @Test
    public void noIssuerUnhashedFingerprint() throws PGPException {
        String sigWithNoIssuerUnhashedFingerprint = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsExBAABCABOBYJgyf21RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEt\n" +
                "cGdwLm9yZ3rfvSuqnA0bf1EQnEstGhA5DCtJi6DDcXnosObaXtDLABcWIQTRpm4a\n" +
                "I7GCyZgPeIz7/MgqAV5zMHc4C/0b582atQFBFrSn+YAtDMPChnu/p4DKDXu3Ytxf\n" +
                "X04TYV2+31MtndB4OMs0IMijWBpLkBFp57ozwIlos+y2gWAiJJ/uyLOzJNYPsEzA\n" +
                "WVbEOrTgmelkc0sYFZlL0JcNsaCmpWjXuhNNulTj2svmwyNrD/3sO2G2hZcGqDDd\n" +
                "zREX0Z8rEAssk4UxJVwOqmvhspWRDT3/UYpAA7sMQa3NtoLB0BM/+/mPG78fmSsP\n" +
                "CmquP71TF3VdbW3zDdeq71apJbGgLdbEKVbwqU7IHtMk3DA469rT0NHdNVbQu0Mv\n" +
                "nbNA43fNfaBbT7ApFQgnzBMF+nBc+HLCJQxq4uRBRX0i2eh+hgFM8VxX8miV1iCT\n" +
                "o6NkMerueuXGFSGU37wGQQMdzOK13cW/Rp1DyFu3L0BSnFpykowdADmjAWhZYCMX\n" +
                "6HAbz8mWRfNbNOahOtCVO3pojI8UiJ9ru7efTA/k3n06WYLndLcI3uW3Bn1F6/we\n" +
                "7IQfGLcjtGngm993hPuCHrg/dnc=\n" +
                "=LBou\n" +
                "-----END PGP SIGNATURE-----\n";

        assertWasPossiblyMadeByKey(SIGKEY, get(sigWithNoIssuerUnhashedFingerprint));
    }

    @Test
    public void issuerMismatch() {
        String sig = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsE7BAABCABlBYJgyf21RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEt\n" +
                "cGdwLm9yZ41vMHyr0Q9WbEh89cDcZt1LU9wR1Li+3wXFW0I0Lv4qFiEE0aZuGiOx\n" +
                "gsmYD3iM+/zIKgFeczAACgkQ+/zIKgFeczCN/Av+P/RqTj8hMDTsoQWggQS3EPmx\n" +
                "5u43yp8JCNuIKiDwTy+civQpAsfWLKhwmHZqokPonMtVSvxH9RFry9x8MpaaQzag\n" +
                "gNO2XwsFFpYa3ce/vjOHv+b9JGfPsSak6RvcPKV99AjqAnxDj93Q9od5DzmWo4jp\n" +
                "i9zt1Kj1AGEgqg/tp9jmmIEJ6ZgjM1sAysyE2YFU0hc0xySKI8+pBk8YG3fj8Twq\n" +
                "d6FDQ3CTvpApdrL5EKW3qW1K/vBvmck15GZOxAsiXaPoiIPDJPxBCy0koK7z/Z+0\n" +
                "vCft+isreOB9B1b68iGdaET9W+bd0ODdZHTfi7KmtG1D8+Ep4oVL8IRuWmf2M1Z9\n" +
                "qI93KxIYqanw0I5HDsfd/5IQ4X1ZD5hoMy+ICLKHQirQzyXL1tjYcw6NPJt0jAHR\n" +
                "LNlerP+KD288SPzu7jymsRXfxp91F1n+UT8n7kG16YARBGhc7hen858EJXn9dtWi\n" +
                "cqP71SMuOwD+JNuWQCd4e1WaTWNXrB1xerzmuWFc\n" +
                "=4ZFC\n" +
                "-----END PGP SIGNATURE-----";
        assertWasNotPossiblyMadeByKey(NOSIGKEY, get(sig));
    }

    @Test
    public void noIssuer_fingerprintMismatch() {
        String sigWithNoIssuerAndWrongFingerprint = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "wsExBAABCABlBYJgyf21RxQAAAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEt\n" +
                "cGdwLm9yZ4LlavMh1EAlex0cmzIH6jHzRv9iaqLPdHi1pM7J65EzFiEE0aZuGiOx\n" +
                "gsmYD3iM+/zIKgFeczAAAIMIC/0QkkD7RcvKUogLhENpeGrQnkGmVEBupHz6V8LR\n" +
                "i/DtlIBNjTRAEwDHcDDfn0JkY9Zp3E4IkNN6cJ9o8vsZvOMu0v9qQKVDwhy6N0SM\n" +
                "BAOCJ+rNkZlXIWM8wyRzt52TWG6CStU2bbLJAq3EeEkZ2+WupCAdsVax0qrWJxQf\n" +
                "tcm2lLQrtCa3gvRtaGCnmW1jrpvkkNZyC/bOBAazr4aD5lgeVtP8Oq3SI32xGV6f\n" +
                "zCSfctIxGz9ZxQGe/VGHmgExkQ6SCaF3JhHHgZt/FCmquIK/IV5WIYAidWmFtQYI\n" +
                "26jVUVUgNHU7Oxagx/55ZXUAMPIspO+J0HOLCpVQUTABBumhgwF6JkVnIn8ZO+vn\n" +
                "GXIkZXQIK1Hx7M4xFYgJjva2ZwxCsENmtDp8FKyeTjq5QTU4Q1WSpJH6KVSpqCVM\n" +
                "hyYvz7nf+kWf5Gm/Z0yGlkDhFnj3th4tUyytvypKgWeZu/1/0+Lfs293OrjjygCW\n" +
                "lMirZ5N3oGYyNH4DQMJ1jeMwdbg=\n" +
                "=A/zE\n" +
                "-----END PGP SIGNATURE-----\n";

        assertWasNotPossiblyMadeByKey(NOSIGKEY, get(sigWithNoIssuerAndWrongFingerprint));
    }

    private PGPSignature get(String encoded) {
        return SignatureUtils.readSignatures(encoded).get(0);
    }

    private void assertWasPossiblyMadeByKey(PGPPublicKey signatureKey, PGPSignature signature) throws SignatureValidationException {
        SignatureValidator.wasPossiblyMadeByKey(signatureKey).verify(signature);
    }

    private void assertWasNotPossiblyMadeByKey(PGPPublicKey signatureKey, PGPSignature signature) {
        assertThrows(SignatureValidationException.class, () -> assertWasPossiblyMadeByKey(signatureKey, signature));
    }

}
