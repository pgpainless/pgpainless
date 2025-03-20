// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.exception.SignatureValidationException;
import org.pgpainless.policy.Policy;
import org.pgpainless.signature.consumer.CertificateValidator;
import org.pgpainless.util.TestAllImplementations;

/**
 * Explores how subpackets on binding sigs are handled.
 *
 * @see <a href="https://tests.sequoia-pgp.org/#Binding_signature_subpackets">Sequoia Test Suite</a>
 */
public class BindingSignatureSubpacketsTest {

    private static final String sig = "-----BEGIN PGP SIGNATURE-----\n" +
            "\n" +
            "wsE7BAABCgBvBYJgW1JVCRB8L6pN+Tw3skcUAAAAAAAeACBzYWx0QG5vdGF0aW9u\n" +
            "cy5zZXF1b2lhLXBncC5vcmcH3ij767MU02jy4exH0wm35AXIhAJQPhlGjPNbE43+\n" +
            "2hYhBB3c4V8JIXzuLzs3YHwvqk35PDeyAAAzdAv+NPRZUqmEokyI8fv75HqZyazl\n" +
            "yLuOOEt7r3mc+riFPNgvM3HCkTtdwdTrv2RY4tOabfaNqEKAHJsnMqB76ikREHw0\n" +
            "1xBDqXdqdzEP1++mMyf6MxleZreQSGjni6NemDwQ72/z5Mdw2bGX/6TLpjlBbQCa\n" +
            "OUzo8QvnhUCl1sFtR3CJWodIrhsjBIQsdGaFgTQ+yOQT+Zb4sLHT0a+To53+FGdR\n" +
            "P5YOqePYq/ZISmp/TXotWXXN3fBt2BzvioXBIYXi4lURqxp+nuxRLRShEMnSh2u8\n" +
            "Cs8qd+bbp9yRyL8jf70729nqt0amV5OCcR+ApuP1iXuSlOdCdqPH5OkzG+kNfBHe\n" +
            "qkG+cjt0UTrbtsWGvypul13urFOUdizX+H/oVMWmOFKsmQYCKaWtv5FHTnrriT59\n" +
            "Ul5W6BXd5fFnxMhzAyo5+cZWgA99e1zFblBGR0OS8E707hFozCp7XP3bFk2Q4zHY\n" +
            "lymkgLgvaY5P+BVqH1ON73u6bjj0d2xbaQ6R3HNu\n" +
            "=bVN/\n" +
            "-----END PGP SIGNATURE-----\n";
    private static final String data = "Hello World :)";

    private Date validationDate = new Date();
    private Policy policy = PGPainless.getPolicy();

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void baseCase() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCwzwEGAEKAnAFgl9quFgJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ/UVV7XCosMuUhTy/p6oxtm8\n" +
                "N+hdaGy+b0fPbzUwOPhSApsCwTygBBkBCgBvBYJfarhYCRB8L6pN+Tw3skcUAAAA\n" +
                "AAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmddcEDg/EFhGBGMTus3\n" +
                "KHu8OaRrjb8q4SKzbdXoynS34xYhBB3c4V8JIXzuLzs3YHwvqk35PDeyAAAPYgwA\n" +
                "kka3H6E5mJIOrBGqJzvDZrsVZcwwVql1mnQM63t1KLuqskzFC5/isrN9uSLM90oj\n" +
                "5QZ5v4C8xUkOj0EjxXc74xDht/4rJlidtsjEFEAJjBoa38YYbn5PdFJ6Z2zH6LrT\n" +
                "kS08u+GChgY4madiU9RnCvHsRSfJPPv6s6jp0ryjtAHMXWY7LNd1n8Gz4B/njEcG\n" +
                "StRa/aC8s7URW4dEB9JshGWLlcDV1tz0IXm6738+IuAMZBuiv9dIqt0SZd1jZl6S\n" +
                "yqqPJzpGI3EmQIVUMMHYLbnnuCjKFScB6Rm8VQaMt9jRja4Ojif/iIy5gVrsv5tZ\n" +
                "89sTltkQ9LHU1ynm1NsKugVs81kqW7mpSuWik5YDxsQ8IQVz2IL8m2E4hn27e+Od\n" +
                "JBFv5NpWAFEIJwghAtxCJdls45muMP/awt0hQwACoaUb4IZmp6DGV0d86JCI1E4N\n" +
                "6R0UHufZRbaawdJ0lgnudk6axeZTh06OnzKQZtKZuBBz0Fw2fi9wVeSQwpSd9cfI\n" +
                "FiEE0aZuGiOxgsmYD3iM+/zIKgFeczAAAFdeDACSXGxVlrQYGXFrUD3Ea5UnHKWT\n" +
                "xu+DtRNV2T4EsFKZKfBKeInW/9RMT7lHIOVLKKO9vZlC2g910ssqTCtTg8kpmXW7\n" +
                "YCUnjR2upKyeqEQZCgJInavHrcysJb65MaDfG2v8Bmg1kGwyQSWLTaY0x5hyDMMo\n" +
                "kxTbLlNklBezgorjZ6XvpJ7WteAxMDqDQuP2L0pEVYROjVFslcrFJBQot8KUOg3+\n" +
                "Nyb3Ne5onzIhprpdJrQjjLiBkv1/YL8a6OMYdEkVogXPXeV96SP0JNzUrURY+IPI\n" +
                "kL4nceBVGpTthDVn3uc6dQEEbwnjAguIGQum18FErdFC1vgXIkxrKAiPc0L/yVXe\n" +
                "U2iHfXQSXWDWahFSZJXtpF0iRjqhx6UigZsFT4nFF96eR+gUafhmlVcU7CZNzFOx\n" +
                "K6nNd3Mye149z5D171YrXEVqThW3oYPVLGmPuJnHneN4w3qQs3fX4YNdinSR5T9S\n" +
                "sZ6RjG6Y7mJDqICYz4LiTtCtimyJOo/Dh6rLiDg=\n" +
                "=CNax\n" +
                "-----END PGP PUBLIC KEY BLOCK-----";
        expectSignatureValidationSucceeds(key, "Base case. Is valid.");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void subkeyBindingIssuerFpOnly() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCwzIEGAEKAk8Fgl9quFhHFAAAAAAAHgAgc2FsdEBub3Rh\n" +
                "dGlvbnMuc2VxdW9pYS1wZ3Aub3JnkKCqgSWXXBpvIJN7hAdcrLweD1Hjwdk+ZJeK\n" +
                "qhIIcuoCmwLBPKAEGQEKAG8Fgl9quFgJEHwvqk35PDeyRxQAAAAAAB4AIHNhbHRA\n" +
                "bm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ6h5DUyOi3iRS2HzZPRJfF25Dth5P84q\n" +
                "3Ed2X6j6gRm+FiEEHdzhXwkhfO4vOzdgfC+qTfk8N7IAAGq2DADQPDlAtgIbPaPQ\n" +
                "NAwdc2DDC9HxNgV0mLwAf5FJesLxckcZ1LfZzFaiMJVx1j1X9eHz6+zxz1C5oi1T\n" +
                "Xt1/1JDmRfW97/E6t8jKBnPc53Rl5sVAO54+V8HebnG/Qvtgyz+5U7nzAV0uudCz\n" +
                "4i3ijbc8AwDwyn9j2sflimBdgYH4XkEz01BfvxiWbZTylB6nh2xVFhujv52WjHHB\n" +
                "sn9uQEXEqGVCEA04gQRu1nGki3aaB2n7I4YrnKn6Mdrk4byS8m5QfgHuZq38NcSk\n" +
                "26WLhFWk8mgm6ikAu86/GOhpVdYC8bna44WiPBKELK+wHApG7bLDrrgHxcbXh5SP\n" +
                "H0KU6jfX+fyVU7iTcrpt30+TD8dPbdjc3XCVciZOyJs4bBF7AckdfPjktBGvIhf0\n" +
                "zd+kCv+oJropfi4FInTmr106cabB7ibvxbxfmg1Q9SfiYl3lOpj0m78jzZ6Fez6C\n" +
                "UnmHCINsg0I2mA6yFBApNxz/LN4QZydChe9GM9JTSkorGfn3/UAAFxYhBNGmbhoj\n" +
                "sYLJmA94jPv8yCoBXnMwAPYL/23zcWEArSL5bi0AiYZ2QXVhb6Nvv/9/oHN8+IM/\n" +
                "QCO32y3VhsXQ6sIIbDGcNlbfzB6NpwmgbC1dLsmtFAtXlNtUggUnl9M64lMp7+gJ\n" +
                "Pyb0X9O9l3sn7TKlHwMxRw0w1oZCXIbwAIp7GBYn3NhVglHuulZOokvEvdnT7jh8\n" +
                "b9+1xGl74FuBvzwXPUaHPlYWppteKDFR6Wz5GO9IIySaEoNn4/CeaYU91BCho5Vb\n" +
                "eRv3LHh8voynj7BQfEz3lZy7+H2E+cIiixut/8xbj4XAGrAsMwi0baGrK4/qfUu9\n" +
                "kJSHYU1vdcPf/rFZPHu6d9Ds+b1JyqQvSr9rNXeeg+Y7vttG8R4IrZ5t24+Fq/Z2\n" +
                "SVyZXKn+2LKGiBMlsqu++E+mnbOKJXT6bRdPTM7OtSnEKr3S9Buk0n50pf3HI9sL\n" +
                "ZqY2h1swA7k35vx84I6+w3tw9BIcgouwouh3LBwzJ6k6e3WttaDet6WVR+fd3E8S\n" +
                "eOIzIauuzHYWv31/BYf3L4WftQ==\n" +
                "=FtMb\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "Interoperability concern.");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void subkeyBindingIssuerV6IssuerFp() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCw0oEGAEKAk8Fgl9quFhHFAAAAAAAHgAgc2FsdEBub3Rh\n" +
                "dGlvbnMuc2VxdW9pYS1wZ3Aub3JnYZGL0zOQWAhbkOoJyPKTyfnjt00b8KbiwDH7\n" +
                "gJDioF4CmwLBPKAEGQEKAG8Fgl9quFgJEHwvqk35PDeyRxQAAAAAAB4AIHNhbHRA\n" +
                "bm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZzW9HzjymTxYbeGK/3iTdTkMeqYxpnSi\n" +
                "UJ9afv+Fwc0DFiEEHdzhXwkhfO4vOzdgfC+qTfk8N7IAANmyC/9yTVyX1F9iy581\n" +
                "t+1fArvGHUPEtzIFzV5WxzrJOy0a5eb5G4pcQ88UtXHNilIsMkxHaKqHzjbc3CSt\n" +
                "tyJ22OnXpAcfNLN9i7dfN2KXNcp9uyNkI/Qoq4CNW0pWLLET7xV3ekyFdv9Yp/4z\n" +
                "pRMbua19eS6hh1h0azI2cvb2ZCcDazWH8EfmCenOLOCGHT8pKTV8fYeljCP4OejS\n" +
                "o1Tkhh5BJSWTTgChoigi3+RzXaa/FBQMr20hyRSVIlt2aeNcu9MzHvqfm6/JtiBn\n" +
                "IPpXx/N8fAa6X44hMGX/ZWPHU6tGlZ/TKfNnqUqmSvdxDU7M8IFQ8/0JMsq4Y85n\n" +
                "Pnx9aWY48K9uBplozYfuHuDpC6NhTnM5Yz2qQj4DjRI+5rCYNCJXTpvnMalqkhf6\n" +
                "PGY0pzn5EodtB3CJF3jywPiGHaORhuCaKMBIFODhHQbCdgbFR9tVYpGvmvumwoZX\n" +
                "os71UxFT9tb/cPpKnUt2uoJ4ajYjYWOxyDl1EbD5ecS8k0QIMWsALwkQ+/zIKgFe\n" +
                "czAkIQaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsecL/jLva4qq\n" +
                "6uy06SaC5GBCNbL4AMnYFedkbbufc0WihxcuKF/cjuUqSIHw2O9x87JyxIFx/ZDi\n" +
                "+xD1LuhkSWwm2bLXlm+uzyHUNa11PKuXfJhdq38xnipZsJ9mVwh2fi5yfVYNWhel\n" +
                "55T7l9MefZyMRcd1VbmX4uLAKIMPN0x/+1wIM8unxDkyVTmDR02cvygxRE1XM9+l\n" +
                "bUi4Nd1QZEc46Az+lgII1B8jAmH8dlkzIdVSigho5HHl5pieGHjsA8KAtkcl1WfU\n" +
                "Mr0bm8ly9bB+UoBFlg0XzRNL6S2RtML63x0fJvIEaWLQMXEdisWEOCCxoBaylzUl\n" +
                "H645R82SKkkKj/rPo0Xo3LDHdNympr7kLwdskBym5OQg28Kk67eQWg7Cv62SEY7k\n" +
                "zTK1/NbYOyt3O3ylt81EvLHOjDqNQ2WMs/N9c9eRT62QdMbsB52IZ7f9r1d41GiP\n" +
                "D2HDeudwlQfZHzn302KkWvZBXQ1hGDg8tkBHXsqxKyQzSNoJ7yrZk2FkLw==\n" +
                "=+yIH\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "Interoperability concern");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void subkeyBindingIssuerFakeIssuer() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCwy8EGAEKAk8Fgl9quFhHFAAAAAAAHgAgc2FsdEBub3Rh\n" +
                "dGlvbnMuc2VxdW9pYS1wZ3Aub3JnuIysm869Dp4TO9T31Gt0znx07pGAEDDkdzrV\n" +
                "Dl4djLMCmwLBPKAEGQEKAG8Fgl9quFgJEHwvqk35PDeyRxQAAAAAAB4AIHNhbHRA\n" +
                "bm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ29doKz40kFlq5U6SXZcO7AIp+8dNhPa\n" +
                "rmf8+w+8aIyRFiEEHdzhXwkhfO4vOzdgfC+qTfk8N7IAAKJPDACSME18C3k9WKmI\n" +
                "fltX4/oz1NDV4iTV+AgMfk2sx02fjCB4qgy2FHyjWRvilNQb4kJcph/63QjQ5Ury\n" +
                "g+uCbOwQTq0ouqeKtZHH+5JybU1SR0oWisUVzPB7PSBQ9yWwg5pMr3FsQNumHeyv\n" +
                "Xa9KjlLnCbIvawGhpg+wrvJohAXls7KdnUUdcRIL8Mm7+RTBP/dKnYUAIY86gYdF\n" +
                "GSzSM4812LxdL5KQWqNzpSPn1dlX0bWtp15S9bbMyFxlO6uQygX6jOZSg1YiqP5B\n" +
                "Xh/9DZAIIDSjGXcUJ8EnKrob9Ko3QC7mQdExvVPO+X12eqjSxAyHddvgMGUod28A\n" +
                "aBw9fxu1Utqry3OvZa119+rGg3v80FCYCcOi1Y6O2va2jxJcJje3yFympwNS8hOW\n" +
                "A+gBCmgS0xojQL0GLGj8pF+XK9HRn+oWjwV2Yavkoi2sq3Xmr7/okprdKkMXR12o\n" +
                "9mw/hg+ms/4vc7r9MJrTs4xoG5rTAfkEIAPlFbATMx1Tb0J/oOEAFAkQ+/zIKgFe\n" +
                "czAJEKqqu7vMzN3de1YMAIKJLWgCTUo8tAZGh7bPnhYz1S4YsOxEPkt569MwtiES\n" +
                "JVerRACdK4ywVzUHdBYk6DR7gsV+FbLkcsvTg/qWFbhZT6CYJaErx1tmQu8oQC1X\n" +
                "YmRXd13ohMO95yMPnPMVUVgcEhUihkVI7QddXpQLR/vJxlKnv2uLU0NZuqK7YCWX\n" +
                "KKhuzNh/CiG67F2bzXgyIs8JThWwpOnsHhTAva7FeXKZGDZY3Tqp2+VkzrhWqUfM\n" +
                "LOVXydn1E49Dg6kM0vF5g/PecyiH3V/s3hUOa7ayK6g0vRrWqdDsFfSlNXwhFr4Y\n" +
                "APf0qybdeGANVCZ1dqDZCYSm9MhWFBF/IOVn5HD9THkHnjLBK8x8WfWcKSoJRo8k\n" +
                "Tfj062dz/dn2JlhYXlHCHCqV4ewK82lvsthSaq06ZRUhta/4mrudxNACXszwmwYg\n" +
                "5rYnK5n52ebpj92fi4btFtAq9slTBrGCDDNHhSDdpa0ymjDsmi6a7SwwwNrxd8hn\n" +
                "7BwZPgxUwqx50GLCYPQJsg==\n" +
                "=t3u5\n" +
                "-----END PGP PUBLIC KEY BLOCK-----";
        expectSignatureValidationSucceeds(key, "Interoperability concern.");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void subkeyBindingFakeIssuerIssuer() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCwy8EGAEKAk8Fgl9quFhHFAAAAAAAHgAgc2FsdEBub3Rh\n" +
                "dGlvbnMuc2VxdW9pYS1wZ3Aub3JnS7EfuJhZoEJrwW8U1+pUyEMhjJcNaeLtWlgX\n" +
                "QwSvMr8CmwLBPKAEGQEKAG8Fgl9quFgJEHwvqk35PDeyRxQAAAAAAB4AIHNhbHRA\n" +
                "bm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZw39jZFOWO0g5eHqzz5H7PJEAXpxyuNv\n" +
                "sY8hyJcqUszeFiEEHdzhXwkhfO4vOzdgfC+qTfk8N7IAAJ62C/9ycniXI3R23dDQ\n" +
                "LSVm7hdxZlpzJSoCOnlDSI0ivRruWWb1rML4HnERfrd8G8Aljn0i4bgpj/R95QpL\n" +
                "NjOVckU4IxFkl9rilhYLOy1xsekknyDBs3dqPT7HQLXpMHWJ+jcjNqbeCjKChh/9\n" +
                "hUW/73JFYSISI3KI247C/xpde3vgPkaAAeGYOmkhtYV5p0+dSkgMHgdzkJtSYxmk\n" +
                "fOni7pMEIT9KAqHig3puNWZxcSeaWNz3cLktrogmipRPkFHdeUf/1YnPBuxlQxRm\n" +
                "YKPhfMXfS1P2g1L+z/+wbUs4lamPuWHMUqjY5naDVY3LuDrAAAjy1K3xGU1AodRQ\n" +
                "y3Zsk1McKC9jdC2gUReQ0eHB7qa+nL4ctasCs9SGK1BO1Z2Rkkw5/FzlWVw1s/o9\n" +
                "TdCjvyTlTv7eCS1wZtZ1RInJD97SePdl7JrrHKhTm2GPRk+nKZNJKaRxw5I030li\n" +
                "4d4ooQthC/7jdL4HEQIkiqGpByErjF+d3bJ+OOsnE9z5FN09AfoAFAkQqqq7u8zM\n" +
                "3d0JEPv8yCoBXnMw4kUMAIJXujMiHqvGWbKKomKshAvGt6wz+35l128oiARcjqLR\n" +
                "+35K7BcatedfVekgRQmpz8hY5gPQ0yxMvVOrnF7/n/qG1uEoaOH74l+W9MSP4rit\n" +
                "Bm7ugcbchMLrlqtXP3I/K8HA0Fxcw9hTFizew3IwiRIzAd2mgv4BUMnasZGJuXF+\n" +
                "5BFIEieK4fjlU0C/Al3gcRWdhYRPvk45LTmyUesIPM6Ggi9+Dt/EUP7Ueoof+/iT\n" +
                "uswQRC+G0iG+vaFNopcIHT8PhYef26vQnH2SgEbewUd0vlOIRrfnbz5H7bWhBlAL\n" +
                "1QmbHcFbXIw4rst37RUYYkus9tIVwIdVjf/I1BjxeY8/kcFGGkEFS7CoQW9fdC59\n" +
                "/zEsYqYTweHtDnLlobTl4bCRWEbwuDSoWlvIrKosLvXVI4Y92xY5rPp4bsPT0vXp\n" +
                "2zVd7+Kh6Qp4ZwqOmCPThqId526H/ijmr1sbDuB3VWwWzfE3r1ZlQzgVDoySsmkR\n" +
                "hmGW5T4PCz3rUZR45xjExQ==\n" +
                "=xBhS\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "Interop concern");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void subkeyBindingFakeIssuer() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCwyUEGAEKAk8Fgl9quFhHFAAAAAAAHgAgc2FsdEBub3Rh\n" +
                "dGlvbnMuc2VxdW9pYS1wZ3Aub3JnI/yP2NMiFpoNuW+7xUMyCFC1EEjF9wre2eVN\n" +
                "FStULy8CmwLBPKAEGQEKAG8Fgl9quFgJEHwvqk35PDeyRxQAAAAAAB4AIHNhbHRA\n" +
                "bm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ7aLfZjdtraE4Ej3NtRGzRXJdB6kHmWT\n" +
                "Dss1LITTLITjFiEEHdzhXwkhfO4vOzdgfC+qTfk8N7IAAMdEC/46O3RvDF3mxQYZ\n" +
                "hsIUBU9FvoA5Wyz7aEJHW2o3XHBtEFB/sLxLlK7mqt+j0lYSNHg6FHi2bjKYBvwj\n" +
                "szzkmpRkDelpmmEHR+GjqSfo1OwL68EulvLtvd+C2a6DsW870QRKjIbqitfXarRI\n" +
                "PcuctlegR+z2l3riVWk7PjULUpCeXqjNUWOQ0AC4p8eFnI7XFZqm311U+4YxRFAK\n" +
                "BZEOFS6e4oV84m0f8Q7CMD4USNC7udlpttG9hU1d9RLvpq/60pIpOEtmLROpJ6QS\n" +
                "73pkLRpd/QWnkB4lU8bz6Yk0bedTa63ppzPXYE6vcnDi81p5KnJ/+01ZLFaObfr0\n" +
                "go2GaTkuGzZpk4JaktxlJuGTHpHEq2/0AMvR6Vn83Jst31J6lfOx34hL1pG08+oL\n" +
                "yQWPQcoLuxtW3+mfPbqzUR+hKKH7z8VWwR3wU7JUhd1en629+SYhvWpGqss7uXCa\n" +
                "sPmCCl5N0G1QOlNwpjn5tnoOxOUm/PGFc7big84j63XSwA8E4T4ACgkQqqq7u8zM\n" +
                "3d1+7Qv/e24OHzfwyz0ELdlbPsKTJH2/5oyRE80kuU/c1nF/PBFBhnI4liTx4Mlx\n" +
                "DJA651dAw8+nEJRYR4diMy8F/oJFvNNHDCPIqfCsA0yrAvK5eXtx7OJRGRp1YF2c\n" +
                "OqElvMrMjeaGK4ksAkPfcAp66pOOghJNlOAiUBSn4aJ9v93ZcI2dg4BLaQeiFHO1\n" +
                "9QlkuK4/sPoOID2ORhPcxZxVHtCV8m47oD0dO9vIATMunM3hbjLrq+VQAeXMhHNd\n" +
                "2qhPHiBoSSdY21RfVxO5OhTWAluJiAyUbJw3EWKRw11ia5d37rf21dEFcDbprsav\n" +
                "6c81n7lMiHN85o5G3KaAUTY1dCFxk/RvjX1j28WLVzaowA9FAYosRnW0X1MsYzcY\n" +
                "zZYStevunDtWzV9guyDWmCuVer8g9DoxERkTT5rwcXwnNgIM/yVCSj7F2aPw5CGA\n" +
                "ed+yt5Eo0GrJXo0lhU0GFLYxjKqAS1ZtjkFrGowgDAgM5Sdfcd53D/aa8nnCCi/g\n" +
                "dy00NMCZ\n" +
                "=qPXy\n" +
                "-----END PGP PUBLIC KEY BLOCK-----";
        expectSignatureValidationSucceeds(key, "fake issuers do not throw us off here.");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void subkeyBindingNoIssuer() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCwxsEGAEKAk8Fgl9quFhHFAAAAAAAHgAgc2FsdEBub3Rh\n" +
                "dGlvbnMuc2VxdW9pYS1wZ3Aub3Jnrziip5I98YkUUBWNKIBLMycCQhLwkb8MuWIx\n" +
                "KlpDRcUCmwLBPKAEGQEKAG8Fgl9quFgJEHwvqk35PDeyRxQAAAAAAB4AIHNhbHRA\n" +
                "bm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ4Jq2etlTzATBYdnf8nFdVsCrk4ud6IL\n" +
                "LGt75G8Cf1tjFiEEHdzhXwkhfO4vOzdgfC+qTfk8N7IAAL19C/9tScp6DEGZy6Xk\n" +
                "CrVyR0iJ4ApBRlY3pvfOIdgYyumhRT0zVoOzuOg1KYBxZh8K8HvkUWBtyJ9gYZOS\n" +
                "LKoca/1V6cPKjjVNXSrosm96lW0mnnDu1pTigdyXQhvDwDUWZWPaxbD11fUSHXZf\n" +
                "nd0sPoooykSJcKLqLh+KV5t6uXlhcjbTeYmHBKUL7qocyQFHl86IDtjxDpaUIFRH\n" +
                "JSv4rvbrqTZfMVLBNG78meIen9+BOzmglL5I0WYGe/8UsocJ65IysqNxdvehZwWm\n" +
                "bYxvd70dpV2lGWr7zgRn8f1rSvjfHcuB/dXzBh89bhGPx4mWj3/1L7IoeXYKAceW\n" +
                "uNUCra/b4ZTo8pjxKRMq8Zwgigio1cGo2Vw+vWBzph3a7yTyC5KJKq398UFgnLRz\n" +
                "OVH1bnJjUD9gYtZQOZJ3STzEpl2wn3CBnGEnY+XCxkBu1PbYfKenpW16it4SxMpD\n" +
                "8eYG7GteWAD0dlSmDxJhQnpYgdvCS6ugjquhJo8v2icBTNKlRa8AADtFDACYtACI\n" +
                "rxBxyZkw6lWOlHCeloMSSAPRgmMfEU2kIYctOopbm2p8PI+pIwCifWs9bSsYJQJw\n" +
                "UoJwGATGskrS1N7ySop+6cXL+pFhn5zYi7um3/LfFuRHu5WZyEjz96ufi8LCghkZ\n" +
                "68EEzXQGfBijlhicm07WqXOheI8GbSqnjVeWS4tXMI6Es2jTn3fLyoxaViBfgZfn\n" +
                "RS1Z98n1G9H16ktvQ8JgJz3zLrK8DPFzKcELGgMTGD0avkmJQJLJcaG5zUIOua5s\n" +
                "JJ8XnwdYmsUn1u6GipsuPnfaOa9PyQdpmtJUtOJ2I5VQk61p3bzEPkFA3wxTtYYg\n" +
                "xEurvoTRb6pHIklILv6w7p8mS3OpahKLZE8m9UpADs2rbghdKYoHcTXTSwuQU61F\n" +
                "rtR1utiXSKh3rlayP0ZTiFY7nrILZh6f5pUnYRd2vqhYc2BgtJfYyCXMksdaNknC\n" +
                "eXO5FsShASzgvtOmfnZLv1cKXHrGcD5euliImmwIBVBWLoKyHJu6rNFbByU=\n" +
                "=WUej\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "subkey binding sig does not need issuer");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void unknownSubpacketHashed() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCw0MEGAEKAncFgl9quFgJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ9Beo7ZqRjM/w/pDHklgayIT\n" +
                "xdm9wZ7gYaMUmORNxqRsApsCwTygBBkBCgBvBYJfarhYCRB8L6pN+Tw3skcUAAAA\n" +
                "AAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmd4d3eOlzJc4xzGFmPO\n" +
                "jGXSE3lZk/qZ9D8Fi9pw7ngVuRYhBB3c4V8JIXzuLzs3YHwvqk35PDeyAABltwv+\n" +
                "PXSY2Mbnp+53M4LAO+8ZA8F97sIiXEIOZEbKpsv540Bb5kzbFD9mRzQit/MpPjsX\n" +
                "mQ9S0BGPpCY4JoF17zukJ0CBsHiMLVMArfx00Ozqtza6MKNXDYDCqoGi9NQSywfY\n" +
                "vZ4dGCRO90aUA4zVTRUBh3XoRmoFAvaWuEm5kbI1EMnYlIEERDeoVoQ+y0oz0O/W\n" +
                "YoNMtJstqWmBNWHSt0atuuAW9Vk5YZLtyGt1dkIcjMaz51ampWyZMGODjdtuJ1Lw\n" +
                "+6qQx9QEov+6NR5q307SGsC7CNxf0Jk+SY08DrypTXZuLjZSFFJmiKAR9ox361ZN\n" +
                "JsEdC6Skc55LmFPae5A+n7QVmWBYP2xW9itJMdQwLVv+69tGp79G5YF3Fxzb5kXy\n" +
                "kjLc8lDkOwHpA4BMx4Y2gel9CgmHqPAxc1EWSGP7+Pp7vxisnv52nPlYcyfS+Oef\n" +
                "ZLf3pSXzKekhrAjRi5wCDuWayYYWdxtmob+CmxDFcAthrnm+yySg9eLo6KyZ5+c+\n" +
                "FiEE0aZuGiOxgsmYD3iM+/zIKgFeczAGf3ZhbHVlAAAfOQwAgmUMG8J7k1SizMQ/\n" +
                "XZo3+HA9CXlRW4sP7ueIpUFbokUIWOaXuD7aPooDK1sYmh1/2H8QHEZ2XBL1eFoy\n" +
                "CtBH2T0XAe9DY1odelgrkTksPIcPWIwOorOm/plvqmwNFUSPuqkGy7wj12kupsLP\n" +
                "ltlXQOD99bGrN7g+rYUkVfraJIoyV1SOPfkb4dm4HVxJ7elPWibUPLs/tsUGuH84\n" +
                "OS7OcZFSaKn15T9UfzSCPCDBosGyW0Mu3pF4wuORFhyP4v7XkAgW6pa2C5kTg1Ke\n" +
                "uJN4nimAjccQVFQfEoQdZ/yQQ11RZq9NQd1hb0CUPCRH2FwW2iy+WMNm7NFLJfcq\n" +
                "cWAtvEOGqzQ+UDCMoi0mRuFFtOtrhqRemDf7ptsOJ4dHCJIySXesI4yAJU5vE+3x\n" +
                "QinUc8dlBtRIwVwYXiF/RulYufyitZkzj07LIH88rTLkuIVY34LZL/1LXMK3PXUn\n" +
                "AuCkzuflPUaH3IgD6oUlefOjgVrOpdpqdF7lIeDiqmCcBu3i\n" +
                "=wp4q\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "Unknown subpackets are okay in hashed area");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void subkeyBindingUnknownCriticalSubpacket() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCw0MEGAEKAncFgl9quFgJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ4mqdkglsZSEUv+46JH7MFy3\n" +
                "kflDcfOc6Fc4pHWJBNYkApsCwTygBBkBCgBvBYJfarhYCRB8L6pN+Tw3skcUAAAA\n" +
                "AAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmfQE676GArevyPBzi2D\n" +
                "FymxZyqkShORqVMnI6b93wTupxYhBB3c4V8JIXzuLzs3YHwvqk35PDeyAAArfQv9\n" +
                "ExFdZd+m/PWTZxpt4aadwR/p6kbn4XJ/GFsLgNABrstLsQNl+B4mIq9FpKvGGnQa\n" +
                "0h25kaFPSX5RLKk+xtlw2cH7gm5bwX50sm7fx8ouHKgw6NhrsqhfrxgxTdJSurwF\n" +
                "2YTiSOTbDV4teliW9/tvH1Y4aZ4E922MBkq8BZd7IbnoZkgVNGRrEHwyRDqfHPMy\n" +
                "HqVYP41Ii1ExnqbSi228NvbkzA4tz1QjveRjGT88cdqL9T/jUX9PHk8e3NENEeb/\n" +
                "iK+SL3A9tVThkoqgG/M2vSIMFvA/QdTw13TP3arzvUivlJQysDL1yRhsU5Tq3o2q\n" +
                "y45xaBon4bXDNmq9NaMHlrFSr9CwwLa/pIlH5kLHA1VAkyQUPqzoG4mH9WHc0jAa\n" +
                "6SsAfSFfP+qWrXru7P5Z8XZ7GRysOKXY4sJxpgNzO5ZIFkQHbSHJ8Rlc6EoRymQs\n" +
                "/yDB+LC0w78utEo5a3tYA2Jq+kkv2+Jr4lORGJT/yA5QF9yoa9bxM3yvoeJZ2Nl2\n" +
                "FiEE0aZuGiOxgsmYD3iM+/zIKgFeczAG/3ZhbHVlAADTPwwAoOWvO9y8oOBtuRqN\n" +
                "tkpp4Nfl8FHTG0FTCpvq7Eara0xJeDO1/s3122Az4UZcyWM3THfGuI/zkWwfJyGY\n" +
                "we4T/DBtfHLLvgIWrYT0MtzN0OoI4cSPbmsZUeCvCk8tXaIDyYL6yJ5GSciscJGF\n" +
                "/n94D/oJK8CYLmRwgTGcscgYUv4IeNm8jX+pEFe4XOhHn86NDC1jVjRg/k+wHQ7F\n" +
                "OKzJx5HyIWPECT+s+hUTOd98euDWA9r0gy6UFoaqN3hxI5HPjoiFzdeOMd6jmQ7q\n" +
                "TtKR8NfVk3mg6n5IL64gfKUOVl0a1Otrh23lKc2lGyCsgXc7q7F4rdELItXPB39R\n" +
                "Sh/6v01Z4TRqxxia7IY2pvp4kZQsWucPCF0BaAq60rve7xpsByxk5dlsW78HW1j/\n" +
                "K1z/g4veCnDFEwSWEUOD6tYKuv49AoqBUkTo0X81TWiZ9N85UFCLFaGrcdOTDrIg\n" +
                "76N4CROzlTnCvmUbgrGDArwHmKS0T4bzj8YdWUt1fpM3zyQF\n" +
                "=ZDQz\n" +
                "-----END PGP PUBLIC KEY BLOCK-----";
        expectSignatureValidationFails(key, "Unknown critical subpacket in hashed area invalidates signature");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void subkeyBindingUnknownSubpacketUnhashed() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCw0MEGAEKAnAFgl9quFgJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZyCXByBmgv7v+Fh7Guk4zVGN\n" +
                "tyP4rBR5YXAgmm9SOa6hApsCwTygBBkBCgBvBYJfarhYCRB8L6pN+Tw3skcUAAAA\n" +
                "AAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmeqajeNWpjGl5T41uxS\n" +
                "X1uVsUOg/9KI1L/MGy33DT5R1BYhBB3c4V8JIXzuLzs3YHwvqk35PDeyAADPSgv/\n" +
                "QFrvuW0NhzOy0n3SSM+OwYTOqeB9WM4xuTYLGNendldCQFWqS4wEbXUnQXBQpfKb\n" +
                "j00Pwonsvv1fXJDbAyJvFBMQSMPETLUbAG3LPpDjVijFd48ULTs0+kQekSIF+0Yi\n" +
                "mAWg+WOZw5ScMoeJI3BwcdkZmarJYpRaLxMJgXyIefvA2c1X9j9PNjJhpmsHluap\n" +
                "YFsQVm17noLowU6k1AXU9CFXbr/33BReSHTslJ+TBWQOwTJZKwQHdB8tW7+YIWNl\n" +
                "Wc6tSXydB6p1SOMt1VD1bO+Af1eu/o/HoVymKmGHt6GTOoVgILb6Gr45bpLx2ZI3\n" +
                "wSGD+h0T5O2weJ5VUy463VHwWI4SVhKBME4hcQOqJac7ZUEisijPpln9FJLEXvTq\n" +
                "nv/+RY3NPWsSPkEcAURFjf/7cMTacY0mZ0dIKtnSuxFXKuwfrLDqtPjw0/ErMbr+\n" +
                "1jDTxraioXdjyDtwE5ey2Ryo2bCh6UoZ7UWC41BND83RzfCOSLW+KQ6/HpVhVZrP\n" +
                "FiEE0aZuGiOxgsmYD3iM+/zIKgFeczAABwZ/dmFsdWUzIAv/RwQsx28Vwg3qBqL8\n" +
                "ghbKn53vxd9yYEOJGAnFjp0wTpFJa8VFhGkIRlw8fkE40uHFa+wpwcceEO0uIYH+\n" +
                "bL6PJBfpSiYIv8v1SCQKnFO5deLtnpsCAXGluwW+Gqjgcn/TMb56hwO2dguZKvfd\n" +
                "Wty+ofzamWQAbhGWD6nUBMlPdsrDRg3q/6hQobmR7SiyDNHMSgT33nHPC63K+/+7\n" +
                "sW3Fw2fTf2esc3nU5mrszZGOQSyuPxhrt6ft5nwleuPRTteeLWPaZydaJO54CJlG\n" +
                "iXl81VqrKOEbgTkrpIUo8eeRcmx3wQ8yDdYfIwdgGuZdRticcQheSMZNuyovbXFa\n" +
                "rWudtAOxNKVmD85sjVIANFsqa6Asw9/0DOElHbUFfWMooptCXmGSD9bFQQivM+CL\n" +
                "izL4LkH2fy1tmX30qNqK0kDMbJ0ScX1ls6YRlzsHnRE8YFQjORDqfWn3TnhJ1/cM\n" +
                "u3MYXS8aVv+onWF07MOJE8l7EmXBHblzmJmkizNf1Xv3PeLh\n" +
                "=Zn8I\n" +
                "-----END PGP PUBLIC KEY BLOCK-----";
        expectSignatureValidationSucceeds(key, "Unknown subpackets may be allowed in unhashed area.");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void subkeyBindingUnknownCriticalSubpacketUnhashed() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCw0MEGAEKAnAFgl9quFgJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ5RekZz/kL+jtCfQCNnRhLy1\n" +
                "tXnRts8o+xHCyW3z2n0+ApsCwTygBBkBCgBvBYJfarhYCRB8L6pN+Tw3skcUAAAA\n" +
                "AAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmdf5RkqzTXzU6IbvZvW\n" +
                "rKEp5vnuigrlYKkuBHlOG5KCZRYhBB3c4V8JIXzuLzs3YHwvqk35PDeyAACqJgv/\n" +
                "WpiJce+MJP7guR3dCGZ79yfCx8+JykgCWB97TrBFIr4zyuG6qEcC++YZzfHc5ykt\n" +
                "DJByy2AwYNxLlcpHkQ9ae1vJQjb/04/W7qq8Nsm/ZVNV9jTOumg6vK8wGI/VjPtk\n" +
                "4v+XPuueLieQocAoEA7CVAk75oQP795HIP8ptWbXrfB08WtohMU3RsEuiT3b7Fir\n" +
                "I2Gs+AfcjA2gFZY7sONCC+bvbXugBJ1AwnBe3yWZp4R/CigGqnPHob/JytD78X++\n" +
                "EceMfLsPIxGOXWZblaUh0MZh5gYdprGY+C1ewIcioxdN/oJ2hg9CZER9yCp7PsSS\n" +
                "kvYKtQaLnoTwAVux7fyzHtWKPawh4p7kXFTXZtm12TXvygWwq91d/NRFjHz3W9w9\n" +
                "BZVg3eaaAWyO9ncBsoSI5cK39/Bbp6sBRCFsa53r/EVLdygBvwbZJtWZewfQTHIz\n" +
                "SL6y04Zkk8ENjWN39OWncYg5DFH5mo8hIQcXus5mS8heRITSPgPmVsQIVJk99Sbk\n" +
                "FiEE0aZuGiOxgsmYD3iM+/zIKgFeczAABwb/dmFsdWXXLQv/Y49KYxR4qmSB9rOu\n" +
                "av1umE8hVVraCNvB811pQdyxT3vlrekNqyhJbB34wh5VJSBeuG6wM3vi1J6WjWab\n" +
                "qqPdJFGbnvIyRjEYeUz6PWDQ3J8ZIIOXqdh6Hxiw9Zpfv+FDV0Xuu8V3ih/hqa3h\n" +
                "tio6zEW+lK5VJwI/LkmnrdzjsVypDVSHUZIsQsMlX02/VMZ2+wT5NuMbH9QE7MSv\n" +
                "CLR40D/761DlSl+UWsvGlZKxKtywEORkWjQsRLXt06BlG32WGWWlDAdj30ZbpbM5\n" +
                "PPh7FckHjkZOJoYT0JJIfcG/IER6uIe1ukawLPfCZtiWroSmH3otx1i9gy4N38v8\n" +
                "OahzVouw3PzOShAscepRucMrETbB1UVzlAKSVjVIMDoKK45DkiDiVXpbUQ3cSuVK\n" +
                "S7oQhOWvxegVC0sZG9yHfasLLwulrph2WGKIUEMct7f78aTnvABZHNhB1BUPLRHX\n" +
                "btQDnj8nMSBf97fNVL8ZyTwjhdIewtU+kVWTr0yL6iKpm+KP\n" +
                "=tNHa\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "Critical unknown subpacket is okay in unhashed area.");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void subkeyBindingUnknownNotationHashed() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCw2gEGAEKApwFgl9quFgJEPv8yCoBXnMwKxQAAAAAAB0A\n" +
                "BXVua25vd25AdGVzdHMuc2VxdW9pYS1wZ3Aub3JndmFsdWVHFAAAAAAAHgAgc2Fs\n" +
                "dEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3JnAbTJJ9IDY5JEWaVrDS1Qlnn3QpxV\n" +
                "UtUI3rQNU3O3BpsCmwLBPKAEGQEKAG8Fgl9quFgJEHwvqk35PDeyRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ2UwGuyOk+sdUBlMryGEd2/H\n" +
                "6YxrWQnpOSam0LNoQ4NrFiEEHdzhXwkhfO4vOzdgfC+qTfk8N7IAAAIlC/9cLfoP\n" +
                "VEBX1J0BZUNm77G/yUgr902+LIsnYxizu3AXEwv1ihy7Dwmtj4PbbnqzFbq09HYW\n" +
                "x3C7PWMWWalCnUMfbOE3vh9oWShsOS2KwEinMuuGopcHH6c0h7BR772y31HV2Fem\n" +
                "9YCZ4b56LvgAk7mGCrI11S58Zh6RwwqadyTSmsbefRstjuHlgA2lxwuQN4c/9n2w\n" +
                "B5Qkwx0ZZ7s4t4IDUFyWHTG20G+/oRFNav9y3CLyhRvgXJ69IvPre/U9eRZ9Zf5e\n" +
                "M453dxP/i8PMKx67j8UFg4yAFQWE5yM2TV2tq4FGINP/7gyFd6F+bwrFwRvwNZfv\n" +
                "0tL94ZJcqC9mW85MFyKwUOx/XMb3x+4Jw7gnYyYEmpgY5/5P4zH+HzKpKNO0JWgh\n" +
                "L3lTmgJgS4E/X2h3PTqxN7uj93fsWBx9lFtziiIofo9n6x1XL+vFeptZI4b9EK4M\n" +
                "Dqj6vD1Mq1WI8wW7Ayc42KupiprxEsMMR0EsEcTbJT6fLbXSgEIarSK7/r0WIQTR\n" +
                "pm4aI7GCyZgPeIz7/MgqAV5zMAAADa0L/i7eOsYcA1xBMymhgqJ/r45AoG1KOD19\n" +
                "KK6OVu0ywZcKXq1dAI8qDwlUsUtrSDCdwN3AGTEmeJug0Gq/DYoEiTNDRsI3uaTf\n" +
                "OViXLds3NUXhyd9HWhS53Q8Mcw9DZvphFrp15ogM+Sq9+WQ7flyuNitzrkOJuqD8\n" +
                "OJZ9rgQRJl0Cn9T17dZYrpMlBDMrMe2oFI9vC/kBgcMrPf49gTT0kJwBx84PQ8ye\n" +
                "7VejWW6Vjyi15H7u8Qf9abitNxHedG4iwuC7AOooyi9H4XvFV97oIxX9d16DmNn/\n" +
                "2kAYbxZ9QBvYUeak5kx4ffFKTN+KmMe8JV8smfWHEuMUEQc0c55oWyyr3Thx7ToJ\n" +
                "22nh8ngVS2mdrqlGBeHyYyY+dzEXvCgWagivhmgt5M+xyrNMUBdIueJXaP6RusdI\n" +
                "SvztVfD/5GR84rHOGcjBdimx0S+pUCLPij0/wP7QwmAvJ0pNxi3xcD7OjDHumo67\n" +
                "mvv6iF1rzSs0UQY73pmGNt20TdHYGaLD+A==\n" +
                "=B81E\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "Unknown notation is okay in subkey binding sig.");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void subkeyBindingCriticalUnknownNotationHashed() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCw2gEGAEKApwFgl9quFgJEPv8yCoBXnMwK5QAAAAAAB0A\n" +
                "BXVua25vd25AdGVzdHMuc2VxdW9pYS1wZ3Aub3JndmFsdWVHFAAAAAAAHgAgc2Fs\n" +
                "dEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3Jn5XlXi/NwcBQfb3HOaH+MrCwYBFew\n" +
                "TELPlTKcOe8Nb+UCmwLBPKAEGQEKAG8Fgl9quFgJEHwvqk35PDeyRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZxsq30hTmOT5b8MspZ6YemCz\n" +
                "nlUOQx4ZIGQQ2uZE+0uPFiEEHdzhXwkhfO4vOzdgfC+qTfk8N7IAAHNeC/wKhdsB\n" +
                "5AJ+cHp45JG+fIXekquGDiV47GktzwXCA83pd7O1I7sDDf5cDbJ32MPKv6+0m6sE\n" +
                "kVNOuW/Ygw6n4D0c7efnuu8FeKUsfaQvZ7GkVxT61p4oRzhiVscH6txekAqJl6oY\n" +
                "eNLavoqcWN1zhng8vqfKgGFnngB4s6l0xY0s96aKGx2et5Mq/0ssP5ZXcdfu0VvY\n" +
                "DahBM+orKZfA69N/QWC9pxpzBG2my8vRKT4lgvLVDW59jiNB/td7JZKicsIzP/hx\n" +
                "wwhvIytb15rBA67PuV71BgirD/Le7Bdvntlvo2mYsSP2UWh5/P273Ty5AfUlsYAg\n" +
                "OHFfNlUlHhlFp4kZIcMVtkLf+AXxRHSd+DGiSmG2QPMg2PiLMODiqSY1o0uKGQdx\n" +
                "GyR376yOQj2kLT3O0x1kOH2dQlIf8iMT4I2RdalafwMHRWLQLbZL6geA/MzZup8g\n" +
                "sU7NN7Nt7fhNNdqaOX5kZwg8gzw8WCHlFvirlCD/ee6ME86Guh7uu2io7GsWIQTR\n" +
                "pm4aI7GCyZgPeIz7/MgqAV5zMAAAt1kL/0WT0On1SqkxYhmr982Y9Bokh9mN9d82\n" +
                "1W5tWtNFY9p32mn7jMRtmh8IMvo4Xrw7ghETINVCG/a+G0YevI1brus8ll9TGL9J\n" +
                "4G3aRjIeTXhQYc0zHjBv+sMgn20bF60osZmpLCwsmhLPVISHeR5UcDsi6H4aZKn+\n" +
                "b/RTezY7IAvIdqtK6qT7BeBHOqAvIPml5YDBHOIGir9/enpCwD41MViyP/k/WHyR\n" +
                "19MJ3VdOrWwwQcFO2SCfhCRoq05lRnwFz8nL5R0acKZFfRcAboV6MrCYozNknjn6\n" +
                "YB6GLh9W51ziBsX7lWfdPYNt+sM8E3HqBk9LNy5hnB9RrZbmlk5MDHEuecc1Zrfl\n" +
                "lO7s5SgD/B/oncmoNhSzYbnfOCr8dL3nQQcTvcexgJlNnyOycPj2x27xMMBJRBlE\n" +
                "YTZ8gx6i8KhOpWlNOPZbPwyVxyXqgLHqO2WMSEO32mFE6BDwQaJKrF2WEUdqKkUn\n" +
                "w37Sn8/HoliO/zNjKtop4L8Q67+ZUKLgsw==\n" +
                "=bvvd\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationFails(key, "Critical unknown notation invalidates subkey binding sig.");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void subkeyBindingUnknownNotationUnhashed() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCw2gEGAEKAnAFgl9quFgJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ+78zI9bWCnULI5khuNhGbcz\n" +
                "IBsZpuDX9gFj1PV5eMHqApsCwTygBBkBCgBvBYJfarhYCRB8L6pN+Tw3skcUAAAA\n" +
                "AAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmeSJ8ETFUXvrKr/cvlz\n" +
                "4E4SVlpqf937O8ddoODWX7h5MxYhBB3c4V8JIXzuLzs3YHwvqk35PDeyAAATdwv/\n" +
                "b5Do4EEi42SK1rixAu4E/2fKq6VWC6kBUNMFhvPH796ZrIt6CPa0bvHTlM3jl6GZ\n" +
                "e0m9rSa7no2kIOFfkirIpvA5xNSMy73QrOQQrpGy+gR69psqY2mZPxC1o49A2l6w\n" +
                "VyT0j56CL7GkZc5fbakSDY2W3hwxDi6YiMCpEfc067iGul+ydPCuQEi/RM+nOjIq\n" +
                "lgpOcI15d/2glDi1FZWL28ah+xneHQBlwp4L2rUvU3iYAbF/3oMGsr+x+m5+JyaR\n" +
                "GaxqCR5i/dZkheOY+/tBeb/iGMR09Gi8fr7r8A8xO7COGMo+JCBUDueFWybQpAJR\n" +
                "52lJb1/XpgIQbwgom5hGo/pkihQgjlcbxZSRgSfuDddeIUJARM3DRIGNKZkM84Wo\n" +
                "JArTMVnBja1aOdPVfGT0G4Vd0nUqSYZop2lQCMIxQzwX+NmPBWeI3LmXC2cBcZdV\n" +
                "OYgoKpUp2xm8MSTJEJ6qzGqmUdGuy1GnRk8DcBmKzFrX5xlucUor20Q+bd8r+lV5\n" +
                "FiEE0aZuGiOxgsmYD3iM+/zIKgFeczAALCsUAAAAAAAdAAV1bmtub3duQHRlc3Rz\n" +
                "LnNlcXVvaWEtcGdwLm9yZ3ZhbHVl9P0MAKxYQGTTnuX1MfEAUmL9F3CfHRANnVkv\n" +
                "f3QNARYaKAChDjuBnRBzYqcUl9jqXb6/Wzsd8ngiDxSkjzVXWPUrkDqIHdEuWjfo\n" +
                "fTcKgT+e6dw8pGSZJe+vE/w642qtV+KMSq6fMIgCed0Y4Y1jUV31x+6QbX+pYknX\n" +
                "Du1cxiM38nKeEk4dr1H+beJuGlch3f1hYBmO+9Md9SvE/SICRZkPcf8wMB2LwWCd\n" +
                "5eWeiXSjtCHb1yOXUNHumRXuvfm4w6ZRHRin1psMJKm9Wsss2mhr2oAPk+L9RjOt\n" +
                "VxFTBbXLFNT+TnE7RLlvFtMDUQDNTZr9upnc3JYHM6A6T5tD+rVaRRovzz1I72ec\n" +
                "IrIZ5L5P7zuWEKugTbR+R5j9cugmYTY7/5mxDtogE+AqXwzzTIq4QAji+U4kMKss\n" +
                "10NlX3TUdUKaKx04uRU2Atk41RvmSTLfI8leDsVDoXtPy3bUDhjGWOqro0AoScTA\n" +
                "P96G+29jGMdTibE1Ev9xhWaG5CjEOVHZyQ==\n" +
                "=mPzA\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "Unknown notation is okay in unhashed area.");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void subkeyBindingCriticalUnknownNotationUnhashed() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCw2gEGAEKAnAFgl9quFgJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ5A9X4Op6NqnOiW+ryPPC7lU\n" +
                "V1GdsrjEP2Ez9HWoL9DxApsCwTygBBkBCgBvBYJfarhYCRB8L6pN+Tw3skcUAAAA\n" +
                "AAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmdirXzFEU0mrtLIU3uB\n" +
                "hOF55yjSF36jWYulOjEM759/oxYhBB3c4V8JIXzuLzs3YHwvqk35PDeyAACpyQv7\n" +
                "BkcWR2FWq0gD05jKYSaftJKh4UyJVScEa1pJXUvz++tR42MUStG9hTIyW3uQ55nl\n" +
                "cnmoXRmhl4lVuAIpdjcNkzt8zcOhuz7VZ5MJ3ZQNnYPzXzHINDklN54zotdRQA7E\n" +
                "OjDiEho0qBpXIbvtKBtZXOrNX+205ytIkm5TDQ2akyBb+e8o4gRmthb9bsVBUsvu\n" +
                "805fbiVZ2IKJUe8M/N+zWnU2JlSUdCT/ysLvp9BRXv9StzuqW7Es44MjQZqrNu2P\n" +
                "EkRyvnhaTfjjiVzpSkWBTBHEuqxdGPELRlsen4lW5JRiW6Mwn2c71yanaNxmUrZ+\n" +
                "rI44F8qqab6dViYgFwnQQJ0CR6Ceo9Kyv6MgFaIrV8yFJS/NGFOfUeIk2xpWmlr6\n" +
                "NxCh3PrlZEUOz95G4/dkQ8AZW1rDOLlToulMmCd2Gp2z6I5uTJI0QmdwKaGEUdPa\n" +
                "OHUtAghUQMzCgI7ndFTUCqJct6ge9etrCg6T9XCcT0BjUW8f+busI23kmKF17YnG\n" +
                "FiEE0aZuGiOxgsmYD3iM+/zIKgFeczAALCuUAAAAAAAdAAV1bmtub3duQHRlc3Rz\n" +
                "LnNlcXVvaWEtcGdwLm9yZ3ZhbHVl73UL/R630rXgH0VIpY2HGqn94B6Imree0I49\n" +
                "GtHjGAMFbHk43nYsaUj0ze7i1bOaQ7ET1huG0kRuc3+G0h9srbw9MdZ3+5tid+jK\n" +
                "oMBcrjat8J1tnzY7taRGv3kcTqSOYBkXyFBtVqBSKzpIC6MfiUBXhnaoUMf3n8h/\n" +
                "CCNfh5i/XVO2NOlgedbigHGWjdREtIJm4Do615QTse173PR9cqqCXc931wtzIPdW\n" +
                "kRHa0DG4Ki7xip7IsbwqbkrHoy5p8wh6KPD1FyFrou49WSE2+T7fs3TBqFUpNTMp\n" +
                "uUyuvOkGYq4LTkXjy62dLs9a45JoEvFijEOId3aqiAn/0e3z9fAqzTNzFdzYjOxV\n" +
                "0Fs2jAabjG5lzPJbeOnj+kWSbv3HrzfXxJxR3t6HAMsCpTarCfZRzvvKv7MtdoWR\n" +
                "0+VlTH7O7XzVn/sKdrCdWzawdm9ON6sG9WCHQcJLqLr7NS0gtU+uRsqi1IFErPqu\n" +
                "3bnuOrz+r1DT6AnIg0odhYJrBtZi83Ll2Q==\n" +
                "=ndXK\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "Critical unknown notation is okay in unhashed area.");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void subkeyBindingBackSigFakeBackSig() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCxToEGAEKAHIFgl9quFgJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZx4j1huZgTuPBEWtop+PgQeW\n" +
                "119LwFLXIgQPcfPnPWoxApsCFiEE0aZuGiOxgsmYD3iM+/zIKgFeczAD/ME8IAQZ\n" +
                "AQoAbwWCX2q4WAkQfC+qTfk8N7JHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2Vx\n" +
                "dW9pYS1wZ3Aub3Jn+eXEmMx3qFeRcDFwACZo4wRmuwz60w/AyGR38+HchukWIQQd\n" +
                "3OFfCSF87i87N2B8L6pN+Tw3sgAAhAMMAMutajK4TqGr8P91ze21QH6HPAL7DD73\n" +
                "/+Ukz7AW1+kuZxd0u7m4UdGZL9n9a7Xm5BG3IkNbWQ+qcjr6SPnfWQMWvCCZg9s2\n" +
                "VdWNI0j87xZc23CC+eOlH9xLKg5ZGicQFf/7rXf+04wSm/O1Lxt/IxlumVRUR7ty\n" +
                "woPhLgCy5T+dl42XAjKz8iA3OaTRCgLjTGHlp/Ntq5g1RC30tX0PvAjITJaxxG6f\n" +
                "+3anTWH+XPioGFBaxKjQvtHtT59M99mQ++hnMM+liY+/1Fm6O4KBS+9BfPaqJxxO\n" +
                "BX5XDTvjkH7ltAqdoQ7FdFfCD3tTEf3im0Rzzk1ly0VDBE1CgSt5seUgLy+t99W1\n" +
                "mixihPxkd0MzCJIQQzak2czu6cvrFmXmsRB8T3vsrvnFdG+i0YmLqA+Vh2hsbTRP\n" +
                "8/JXjuyWpjpFc4aZXi5eYlCUBkgrQOI/ko085/UQbYIlPNPEEXxZ7BnWjAOs+6XQ\n" +
                "ISRrrPDLjQZ7h9nCJ3B6DwpZ3o4IzoDUccE8IAQZAQoAbwWCX2q4WAkQ+/zIKgFe\n" +
                "czBHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3Jn/7apW+no\n" +
                "6a0cwGESmPJch55Fj23CwydSSF6OiAO/5uEWIQTRpm4aI7GCyZgPeIz7/MgqAV5z\n" +
                "MAAAeXcMAKVjNxQ1URi9LrC4KZV2sM0lge6cWpZPdOOJ/fsaN0KMOgNEDZwHXToG\n" +
                "nICseSMU4wxTn9jeMtgjC5Ld1Unqob/uW004DGp5XkVrjmwQvdc0/lbLzulBtmv1\n" +
                "G9K6e3Tdbvh4sP6L9emWIi1TlgUflFo6w1rcqyXVxCeDJe+teuIfbi4JsNnut8VW\n" +
                "AWpvgDhs81CLrH+ueZVtD8ip2WRCstkcXjGzg2M/YNg18fUlb3p8UVXwcrQ/UrZt\n" +
                "OtyX+ymF+w5sx5O+ozb1JvI81kS2g+T1BZ9IuTxEKgDJBbd6DoSfErkbdcl2s2+X\n" +
                "0Xr5oESyGfAhKFz3g69JX33PAa+8RH+VnDwLLxqNKyAqe9q6AFIzfXn1o6zHeZvT\n" +
                "9bbj8qV9lHOJuL4YcRntNEc0PjM8aBgbcjcNNBqgyDwfsxcDg8ghb7Q8famGwLk3\n" +
                "3mSDFT2MBe4irc9qNsdUZcfrBc6Maz6bG40LzIlX7RMj4oqniqqcZohlXbhAYLGV\n" +
                "5c367ssWGIcaDACWaBKtGjOVZuSAjG+G/KDMpK3l7Ce9uQ7jwbu2C2rt8Nm2th3L\n" +
                "Up199uO7yBWEeQZX7egB3cc1etiibSGpUy41sQpsptW2oi9vup2ltriUoxBZApQy\n" +
                "2m1mDq0qsXYSvq7W6ZvsUE/jFRHs4DFRzlKeopEs0fcT7gbwIV6FRhDT4Ptz4fkt\n" +
                "O8O1sc4ga6ORJBgZFkfS3m34QGso/Q2VVn+uAWmUnYG9fQq/leA6pIM9XH4vPBwp\n" +
                "h40gItvbU5BihRp9bZYXkovuj80AVy6/Hzy9eGJHrCCjhl193kJxPz12jxMlbQEV\n" +
                "eooALtvGzd8bsiP+RJwJrG3eBrlj/k3gRxKBivTJu2tCPZy6uWz2Q0/8I1OeiQ3X\n" +
                "HRrhnDjrQFmfXqYRbZeswAtxriFem9PALptlVPREt1ZbItlqxsg3cySHcQ/9tUDt\n" +
                "GJsxCxXWzEAWbJ6TbcB76hJRhaA/G/gBDqN0fAdRm6XCAsYdNxivNfg4ORTdrGJZ\n" +
                "5d4KXVKpFMKWWMg=\n" +
                "=YAxx\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "Back-sig, fake back-sig should succeed to verify");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void subkeyBindingFakeBackSigBackSig() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCxToEGAEKAHIFgl9quFgJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ0tcIfNHkSOzmes62+vWg3Uu\n" +
                "CCyYXJjP6+1O1lGijkDBApsCFiEE0aZuGiOxgsmYD3iM+/zIKgFeczAD/ME8IAQZ\n" +
                "AQoAbwWCX2q4WAkQ+/zIKgFeczBHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2Vx\n" +
                "dW9pYS1wZ3Aub3Jn/7apW+no6a0cwGESmPJch55Fj23CwydSSF6OiAO/5uEWIQTR\n" +
                "pm4aI7GCyZgPeIz7/MgqAV5zMAAAeXcMAKVjNxQ1URi9LrC4KZV2sM0lge6cWpZP\n" +
                "dOOJ/fsaN0KMOgNEDZwHXToGnICseSMU4wxTn9jeMtgjC5Ld1Unqob/uW004DGp5\n" +
                "XkVrjmwQvdc0/lbLzulBtmv1G9K6e3Tdbvh4sP6L9emWIi1TlgUflFo6w1rcqyXV\n" +
                "xCeDJe+teuIfbi4JsNnut8VWAWpvgDhs81CLrH+ueZVtD8ip2WRCstkcXjGzg2M/\n" +
                "YNg18fUlb3p8UVXwcrQ/UrZtOtyX+ymF+w5sx5O+ozb1JvI81kS2g+T1BZ9IuTxE\n" +
                "KgDJBbd6DoSfErkbdcl2s2+X0Xr5oESyGfAhKFz3g69JX33PAa+8RH+VnDwLLxqN\n" +
                "KyAqe9q6AFIzfXn1o6zHeZvT9bbj8qV9lHOJuL4YcRntNEc0PjM8aBgbcjcNNBqg\n" +
                "yDwfsxcDg8ghb7Q8famGwLk33mSDFT2MBe4irc9qNsdUZcfrBc6Maz6bG40LzIlX\n" +
                "7RMj4oqniqqcZohlXbhAYLGV5c367ssWGME8IAQZAQoAbwWCX2q4WAkQfC+qTfk8\n" +
                "N7JHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3Jnsh34aPPs\n" +
                "PwoSqLVIbtJWRuKCtHwDLgs0UZv3eB+MVEwWIQQd3OFfCSF87i87N2B8L6pN+Tw3\n" +
                "sgAAJ8cMAMxxsaYRbzXnSNLQnEns8O2lDe1RCBr149vM8Z6BRghxywb06c0yZn99\n" +
                "VAFYUaW22jODBlBOGyOcZgt9rfeeXxCsylPPRJZb+xVVSmfl2AGHd1udI1WtJv0F\n" +
                "UhwysPplNT2WBuvKZuxpViEPtlTbsxdJCyiOtI95rJpa2/PCwchkgZvNWjjvc1vC\n" +
                "PZDUP6Z9fsA2Y60qzr3tFZkFLm2ypzRAAdcUmFHvyIkyFGjvgJHVRdzls953dGgI\n" +
                "9Ku16kXKS600YMmx5K/mIIZKZwGtWbKcMnqBKyHDBXz/zaIIaCwpCHq5x34Cr9ET\n" +
                "9qr78l1599NeOE0A0EN5uzN1YbF/Wbo5mngqztcPe/vhrrMbLVM89lHB9SzJJddI\n" +
                "Y8o4s49Z/9TGskYeHHdMKfzqrbBPhetPWqN2PFl7rQQKJs1XwajR6R+U1GXdpfdX\n" +
                "FywO8TXMx7wgA9c9l0tFEdpD0orc/bcM0W2K+5Knz+9KF2zAzoXkki9zYNqXYtAj\n" +
                "O7mWQMP7FGCBDACbJCRyR3nekjnnj1bmoSqw0CKsFRJ65tJ8a4L2+ekvpIsNU4di\n" +
                "37GX+bnSKJdTCNLzFWoD6+GHLTHCuqhwR8SAsZ9RqsBi68GpmpDqnILvqgbGdbew\n" +
                "tsHWuLAlreAE+TMtLXVxNdEFPp9XvBhHVcqvuMRrJgJ9G0hPof9Bvlu6kjnBRPp/\n" +
                "IteZmU3+8uQ9hW0/Yf0N0FaXBrYDfVwPzYogtI+WQW67v4SVprdoZUdXvS14CTqU\n" +
                "jDVTFRdCViKs8ERnMzSZMF8ewxBsrD0zJtW3Ui5XPKTx6CMljusHGwXEAGu5q5Hk\n" +
                "WTO2forOj0TNs5eMAGTPUTELJl82KoBszjhw4ECYok3/3rlKd0/p7dLP3nXXa2TL\n" +
                "sRMwfBCHIE473J5NIAChn5vsdSNaVJhjrz+L09MiX36QV4pW0kg8Yx8Gxux3X8Xh\n" +
                "7axHapIZUvYWn6HE8/cd/OYSf+Ab9MDiprwv90P+cxuaZmREfif3H6JeG/tcvJbp\n" +
                "zakcV1gD8cov3qM=\n" +
                "=IKlB\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "Fake back-sig, back-sig should succeed to verify.");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void primaryBindingIssuerFpOnly() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCwzIEGAEKAmYFgl9quFgJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ3mNHCnyvnvpKC735u98RZYQ\n" +
                "evgMnqBeR+MQKnizgGahApsCwTKgBBkBCgBOBYJfarhYRxQAAAAAAB4AIHNhbHRA\n" +
                "bm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ+M35RKBIWTYI+BMH1QBo/G2i07Z0JkU\n" +
                "29acqwvVxML7ABcWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMKSYDACBUEWuwcT8j5A6\n" +
                "RznKsxdhJbmvpq8JydWlmkVEzqk26kUZMog/BczRvapNjOxGmKrIreZjw1j6FmcW\n" +
                "Q0aHItiwKLrRBK2PcNc+Dw0Qai6ZEzf2/TErNG51NCOPzJiYnhf4oEhOculYE8sS\n" +
                "CtYHnuceRUSp0DAZpIPgNocXtVvJYOQX3veXeZvKhpAbqgj1gdpqIT85IH7LccT4\n" +
                "f1ZrgXLw9kXCw0S8pF1MgBcu5FccoZqugODqOi386luRoBgvyc0epqGpXZLrSyrj\n" +
                "kxwgWOO8avk9gLceoPh8DOorAGyGHJ8nf4jVdGa/EaR7T4LAJT3AnaWnNpCuNVxg\n" +
                "8Vt3PKw2Qouyi7aBCxjgqt9mq5bdqMGhmsFmGEUYhLMlSo7doa2m8TYQH6kiZ/LD\n" +
                "CZ0vvBD7Kd0I7GCucTUFCJf8OY8YyO7ms+k4wx44l8D1b63OTCjlQcGL8zZcfN/o\n" +
                "cUxn60iEX5rKyWFHXFNnpsfLdityhw1qMMejibczZS7VZ+UXGpwWIQTRpm4aI7GC\n" +
                "yZgPeIz7/MgqAV5zMAAA66AMAI66ZcRoABzjcNV8ZIZypRBuUp+fZgugT2NSseEw\n" +
                "+QyUKGUhV2uNIFi6ycTNB61/XZoi3PMXxI71kUcz3QjYKPippCnUO8wJ5SwgdbYP\n" +
                "ojc20UcCRBxp3G+Fwyorn7nMj2JwHVTqog5GYxppozU+Q3XB/we/6h61haTsFQFY\n" +
                "b3ijKanoRKx+NPXCrGndR8GGcfK79hsMCy0FWK8v0svN+VgD1rmUiZhjM6EcabMr\n" +
                "zpZHH/QNAlLM0qyxZNhK12OQC/+5cTKs4E8tKzymxZA+hj4YYMpq8JNYlf99T99Z\n" +
                "JySBmOI6BJkKWXDOhEul3Sv6HAOQgPIyzcE08K0+Ua6UIr2k7+09/L3nyFd4nbe9\n" +
                "I5kbpqAWVIU7gmCU8X6+w+MXoZ0GihUPV+BVks/nCE6o4m4kZ9tKjp8ATOd4AleM\n" +
                "gL10P2p2qKjJEzi+5Tx01m3IQVR1/C5qc8IbpHWlrdMeNNtxk1wR14pSmGqqdIxv\n" +
                "tGjpZWhbyGMEJRKO5gDGIQCdaQ==\n" +
                "=l8cI\n" +
                "-----END PGP PUBLIC KEY BLOCK-----";
        expectSignatureValidationSucceeds(key, "issuer fp is enough");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void primaryBindingIssuerV6IssuerFp() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCw0oEGAEKAn4Fgl9quFgJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ4/JcCy49EMUYy9weIfUCey1\n" +
                "UvVmAhmu9DHyrWOyaPq6ApsCwUqgBBkBCgBOBYJfarhYRxQAAAAAAB4AIHNhbHRA\n" +
                "bm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ3KrT0/A1W+kFOEXKp53viMgTLKT7TLU\n" +
                "PRDMQmMA1KryAC8JEPv8yCoBXnMwJCEGqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\n" +
                "qqqqqqqqqqqqqtLLDACQjnaPl0QZCuOxBSG8lNDUlFN/N65Ol5I2s0IFOOofc5q9\n" +
                "h2MSCs66HKE18wxB25nVMFM0bpcBy7CjXs6JfKzZkbMOWiXzWt/ju/AiwoIoF6/0\n" +
                "Crd/p4un71+XaliJ/KmKTqV3T7V8DQBa08wjqC38UWt7/q57h/Bi1sfVvfLB3fhK\n" +
                "Iem3MkLj5thDEnyWY+MMyPk1o/aneKuYRlVS3wI9TeSXFEAB+ukMvtNKF7vKDOJa\n" +
                "5mQmk0KoamjJaBWXcNExZ28VMdKGsO7ajQkTv2w40ckhHuOrT/BQGTIehxjViivY\n" +
                "9NfMkHuuNH5y9wBUv5JsC4Mttx8bpWaMZ6TK7Jg+bGXmMecEAFDvi1gOuWMi3+PX\n" +
                "oOQJP40c6iTqQCJFSHWlBm+oDFE9mJ8tSgvydlLLNXWop8omvqyIPkMqqxNexjRE\n" +
                "O2qWQSf27GhO9PaOzapvGU51wsrDIUg/+vqzZt013Bfq2oDxKrWvxODXoMRijQ5/\n" +
                "+mm6vHr6TkfdYwxm+jMWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAE7wL/AyD96vd\n" +
                "H4MUp/CXrhll5mnqOhvYaWmviuEuB3yNMut33RSszVOj0aPvWa5sIngiot++oC6r\n" +
                "72X9ejBLxBJVJxUrwiu9u873in6EaM4nZWVwq96cP1Dp2QoBKnr6eKPrlX8caGen\n" +
                "MdtmBMgvbgIshNweWnIgfTsoHtSqNoBf4zmdNsJdKvIudVDY3Pet3x9j6dr5+s7t\n" +
                "XdLEDVVZCg8vxi1D6R8mvz8bW1RBXk3lSOi8x0tcBEt3sO6JmUeL1QWzhhKhHHIL\n" +
                "lPVqf1PvCI832GzUYUy1cb0S8XFDtOzbHts1H6Mw4IMnAD5rYxKgYaJsn1qyXYu3\n" +
                "GLPvdrjfvg9NfWS9o7jDFDKPTtvC4Me+mo69sPG4NhWvsOau9BHAOTeA5R97o/f8\n" +
                "NaYlYtNehHQ60Xku5Ym/gEJcgkKiH+a00T5JIy/ZhdzwABrox7V1sLi2cu8n4OGU\n" +
                "FYwbyL2JhPUqSZGHXNVyPBRLywbo2eBysdR8B4KQv1ZijKkH1xmFJpyC/A==\n" +
                "=dNVx\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "interop");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void primaryBindingIssuerFakeIssuer() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCwy8EGAEKAmMFgl9quFgJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ8HDDLyl3U/ZEz8Xzh/gErQ/\n" +
                "ZA40mTmhPodMAMvW/9OIApsCwS+gBBkBCgBOBYJfarhYRxQAAAAAAB4AIHNhbHRA\n" +
                "bm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ+AtTgOtdwuMAwktSnFQ4OTGBScGeiVc\n" +
                "RisSbj6pBWfmABQJEPv8yCoBXnMwCRCqqru7zMzd3SnyC/9unSC+vgrI384oR6r0\n" +
                "L7ZteEGO+oBmZP+idrnkQF/XTbkg5FK/1fPjo/qWaMWT8QlpbWka+U/BvqP0v5fX\n" +
                "fU/YUo+xe/nne8PAtcH2bCw0zAO6TQbErqKHdxMz4aMtwqdV+I6B92e/a/YUJpzr\n" +
                "Iexa64+vFVofMX/AQl/HAXLdlnun5LSDu4evNjPu52oHDCpnGw4A29prVf8HaqyX\n" +
                "ZgqhYW0VDtO/6kZ7Yygv8qnWCM4q7GZ5Ht4HqREjV0/lNt5799Xigk9LrogY3pSO\n" +
                "9eNjADpalDP0PhSob16Zq2eBmS1w+PTFaKYcn8SJZGYm6Xv0dBr/fxfVD1SBYfqj\n" +
                "LBdSmqmFFMeVI86Sh7lY5hZ4AXM7ydH8hRDB2n/AlarxcAVm91su3+IKhSfTD7t7\n" +
                "zKYq3cForU1iRbka/h6juw7gP+7Ob9dvKFNAz4xRDCGoaxlQaD54Ug7XTl9o+WbP\n" +
                "cC1KXPKM4LZAQfH5u1XGzuGg0hL3kqwi1ooeTTh0ClGpp6QWIQTRpm4aI7GCyZgP\n" +
                "eIz7/MgqAV5zMAAAqpQMALjPYbcLgnalQHJQxu/AlkAnbbGjzDWjPBIXPkU2uIYf\n" +
                "sdGMSzsAPpIoTgjVDYxnuZVe2W1D3ffIxdKBmKfdPVpB/uWnYUyxllVk3gsSUNal\n" +
                "/9RvBIguy+pKBm1GDvM9hJHajfsaCmg8xn5TJ6LZxyyuQLl3F7H957ne3P+eLcL9\n" +
                "3DGKVwFhTwKYbCCI22coUcBFfoK1w4N5EAUPghubAtwRJu/dCXsuNTU0Iw7wgBLu\n" +
                "P5/5cwk0YJHGI2ObXDyCyj1j4a1LFxAHRWUbzQTMjG0rRo1nDW2n8ZMf0uvyoBGk\n" +
                "SDgqq/UAGb5weoz3LsDy0e7yahFk0jedYD1c5AF5HE6VztO/s2epZTaBgyzFNmTL\n" +
                "McsiEtc+kYn3wRIYB7dkAaNgkCoW3cgAPov+7Afrm4ZK+HYVvDUyacu2AWRmGc/F\n" +
                "GPSDz3odfrDYqdtIHm+GgbfVXk6AxRJtGVs7dxRJbzn51Ca7k+tJ07oc1AocJ4yz\n" +
                "Id487EfRjp273t9x/SACYw==\n" +
                "=WHjR\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "interop");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void primaryBindingFakeIssuerIssuer() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCwy8EGAEKAmMFgl9quFgJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ4HBgY4fgT5AVY/NdHlnvncB\n" +
                "uJXK6Jy2WJNKmyfH7i8YApsCwS+gBBkBCgBOBYJfarhYRxQAAAAAAB4AIHNhbHRA\n" +
                "bm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ9bRFPzvifAat0hEFgWmcBtMyJJIg+Rq\n" +
                "HSv38jVtWRm2ABQJEKqqu7vMzN3dCRD7/MgqAV5zMOPQC/9cG5QFzYnONzVoAgJ5\n" +
                "X+H5EYQni5iv0h0CXnjEN+H/eX+by51QUfJzK9rpO7iU0FxvFUzrnTjtmNKIk9Yb\n" +
                "mCTYTwK7VlpODl8CZKlHb47SZgeJ5N+yRaIlOfiAR61WrSNgFaxevPhpCBJTX3OG\n" +
                "B2x2xZ2SiKAZ7WJutXHanXk1XSLjmwtg4/CCmSvqxln6TFgRM1oS0JgtToD/JI+A\n" +
                "SIdUWagD+fRXZA+UDoFVWytp62NVtIYYu4N84ydh/ChlSJtogCDCD//LNFq3wA8q\n" +
                "hvfTsMzIxQApfboPsRkVu/uMyqYe9RFH3IQ60BrNLf0KH+QcA7ZizXv5OCjzOADo\n" +
                "5LCDfzxF0Lpoq0wWcu5okkKu5oQlOV3VcWllxpXKSyH/TsD3s3OPu1wHtNiFtitl\n" +
                "ZB3n/6k0IN2hkFXYz/88BJAatagjoR1uESgkS2cWWlHEG8K+2n3aw+hxTZlAMHrM\n" +
                "BJCf1e8w8aTYueotrBPUekb6i8uWcuiXM6AXfuM/QoEqdGYWIQTRpm4aI7GCyZgP\n" +
                "eIz7/MgqAV5zMAAAvkcL/iK95vTAv1XSzFosv40eNF468pcOzBEXmSVwRAl5SfHv\n" +
                "O4F1BMEWepgl5sD6F6M0JK2jF6qMSrPQXKg3vSNUnIeT75+xhJmntH+yFyvNUstM\n" +
                "Zp/fLSlAO4Mf/eQ079Y+pzKGGEjseJIWvi9tEC5vfRpJauc9vOSdnA3GfEhV1XC/\n" +
                "i8axfxInukzxtZlTIWowERfpLlfvzW70jCcEck9nZGnD85r6A5zVl1lE78OYi8Yo\n" +
                "gmnRGOQc9AA3Gk+DaBWC4s/NbSCpNp1hpRE7NBP3ljXSfebVideplA6Xzhm3zyEi\n" +
                "fSRSdDDSIclMMCqHIyJkQFQqaHctmuYKCw6iBUS43ofFxJmkQz9WsNW0aACi+5OW\n" +
                "VnF8jE8iCDCv5UCCLNHlR+fmWC57syun0zHGTUQigsozB6AHaqHuhjGyL/cM4V0G\n" +
                "z/bspldp9hK8Qq3vuKIZNsdBJ5yywLoq6qLc65DTWEfa44c03ZAg+PgtjJL8GzAs\n" +
                "MbE6iM6nzl9szxdfZwM9fA==\n" +
                "=9cqv\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "interop");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void primaryBindingFakeIssuer() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCwyUEGAEKAlkFgl9quFgJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ7V8oqSS6/k73cnFlCAmsAGS\n" +
                "aGZH1zQ9IZckmNSy4Xv6ApsCwSWgBBkBCgBOBYJfarhYRxQAAAAAAB4AIHNhbHRA\n" +
                "bm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ9V5KotwniJdgKMu+ao4RRkHpjHCGJXT\n" +
                "dSIuAfv/QqEpAAoJEKqqu7vMzN3dHtAL/jhtpQW2/6jD+3U2RHveBjirYc/KZMBC\n" +
                "CkvQ5ewcx74GIEFzhl5CnQAUhhE6PAHFXMOtDbV5XiJQyKGiObZiNBJKR+N1vMvj\n" +
                "2++idJvmFu287rBEQSd7eXa+EVD3Z9wQ0QprCMenD/nQzFuzMqtgMqZ2KrXE1356\n" +
                "qHD4nhIx19G2l2shsoNdG7bywBl3/UivOtu3xXvbigxW8eUfduWN3z75h1SY4JHo\n" +
                "55iHt5Apz+PQH9Tyf5+g1CTm1hN/kn2kfj6vho8ovQhGHfp+ahnyJ5m8R08p1hj3\n" +
                "qXKShmsfE1wAbM4mq/xtsXYF3TL+QugtldlAzF9KE9aW9pfDlzg573N8Eny9yox0\n" +
                "1WvXislYwOnKTHZPHCpOLbLyQrtAKo9eNJTyUs2ObX5LEGOVe5nv3a3Fji6pF9eE\n" +
                "42dTxpRTbAfuBBxUmcw12F//UyR7K8ooG9qXmQ3SLLlLRPUYAym1iMiz0tKOHzFK\n" +
                "LMcyyDJve60+ejHtf05XJiOdj5T0VwSBahYhBNGmbhojsYLJmA94jPv8yCoBXnMw\n" +
                "AABXOgwAr5QUncI/GzGaTGk7/C+KXjhVupJ8m45na9ZEpH9QFa4cjMDQkk66x82t\n" +
                "g6UegI5cLYtz3xkjY2Tty9P9TZZHGveoMXIvF7Jr8HBMic1OBzN2Pr03PPCr5/qA\n" +
                "lqfkUzq3QMF3IO5tKkiwsKppRIxg/pKxWlLV14HXm2+8cE0QeodTC40WisTcpgeI\n" +
                "b57iWNv45q3DbowCl9YRFx4mpFkdGLLpUbZNKF9D4HBCSrny3s8d2mq4SttyKOiI\n" +
                "T0Bu6+DVhNwgJbI0tTvXWlN1FnrXtvfgyN48X9cGTyB/0ROgVubEqaW1XysRWsoG\n" +
                "eUWzAw0o0clK+oKWXL7zKXI9ORAnYM3YTlD9B6FDQAwnFiXD8R/KR/KssSYcYaUo\n" +
                "yCs92odoOtFLTyBITo8AZ0We+QevYMa8gBuwFKRQI7+baJBx3Vatfp9fIInwSz4b\n" +
                "rNuk8iSLBJzINxaFVboWhVZNP0s5QeAUHZ4e7DF1nnXMMVRMeV3TxBHjz/blb2nU\n" +
                "hQmcUKpz\n" +
                "=wOsZ\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "Fake issuer on primary key binding sig is not an issue.");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void primaryBindingNoIssuer() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCwxsEGAEKAk8Fgl9quFgJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ4vCMa0q9umOm9NlbhclsKye\n" +
                "Szu1zKTQSc2HAvNlfhDdApsCwRugBBkBCgBOBYJfarhYRxQAAAAAAB4AIHNhbHRA\n" +
                "bm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ/JFqKSBD4+vLRMlThPjkvkV4M1Bmjzi\n" +
                "33vXtwEINsHwAACO/wv8DZYl/p2PeNtqUF+l4swX3jgVZ9tjQeUTpfEQsfSdbg8w\n" +
                "K6uMTmzvWRPkEMCw5vsoh3D+UwWQ+PoSyewKoI0apNTnkhyghtzeSJQBMOIb2dKi\n" +
                "x0dJrhdKFqzmUXSFZCQ6ELcZ2wd3qjNN4tE05BKso2nwFxY01M+8Wlta+TgkCIlq\n" +
                "2Z7grSLxbbMIDiWaOFKcgiNlAD6w7+eUuHCkSFvj8v22Eea6sIC7fZTOKga+/9JI\n" +
                "S6UR2XDDYxDRMjd8KLdFbFbYjKYuxspVtlfeMdLCnLck/BC/xU38sNFz6Y+7Pmpi\n" +
                "LNVnLjz7Ds9oySW10uOCMNiEa1QH+hpqr0EreojA1/OV0qEMTBbs7pNGR8K+SPmI\n" +
                "gNhHNIJ5lkS0uUKu77gUh5ms49J0/yylw0xImpAALkrFvzid8dkkkgh9vLXSjsPO\n" +
                "zIDR0NTIW9SC60rfGwHM6jHkQNwOB+JuaXJ3QHKggHwjgDaRN/pK6vZmNfSzvczp\n" +
                "MEMtXOHcfSyAe40V0EZdFiEE0aZuGiOxgsmYD3iM+/zIKgFeczAAAMyuDACMUTX4\n" +
                "u5/Mn4n2mJZEedE2fDQS/BM6wHt0Fy/H6bPGT3TLIwCy34DSWw/P0MnTkqTHnNw1\n" +
                "igXfaslmWh81weaj3VWZunFlw4f8JP4l8HLh14FS9wN9tvxXew4Ojga6MTwyJCQa\n" +
                "1A5OXWA3XW42whVJSTcnc9XC5uYSokhvfzJG882+mETYUKdzymeZ93A3maiCMMME\n" +
                "Wn4zFFRPu4b7g6shUzEwd7HBXPBk4gHguqsLZa/750V1MMYCq9w2+jeDIjK7xzrS\n" +
                "iqFOUslNm4oh69bt0+whmH7JOjA7CBNp2q5EVQb7V+0+Dqqkm1Ilk42naTnxJ7w1\n" +
                "VfuJ75UL4Tr6RvgdSr3aU9L55gxdS/q6OapZfbF6bMCTeWS3hYxFifcbxaIHFMV8\n" +
                "PPbaPPvnT3eFIBG23A/2H5Exlc6nC2MsoX4sSZOvqs1GkyA0PmMtqJxTPOtcbP+D\n" +
                "9fCMzEb5VZu4PMZBeZgK7kzrlqgntOKc07dwGrTMnFKWfOVuClpB9bci9eQ=\n" +
                "=CxCD\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "Missing issuer on primary key binding sig is not an issue");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void primaryBindingUnknownSubpacketHashed() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCw0MEGAEKAncFgl9quFgJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ34gPwCpcb7vrLGTav10QWjq\n" +
                "YOJSQ2Aslq8DB8VN6MTKApsCwUOgBBkBCgB2BYJfarhYCRB8L6pN+Tw3skcUAAAA\n" +
                "AAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcme0oIUzBb/FfSG8bmOL\n" +
                "GQylPSAXq41OBJu6+l1B54ZdLRYhBB3c4V8JIXzuLzs3YHwvqk35PDeyBn92YWx1\n" +
                "ZQAAX6gL/0M+enlEF2hSCP+PwPuL+hzSRGJBnzHGFIK8VVdMIgxPiYmKA7SO1+Ht\n" +
                "TXYB5gIqQV0dGNyZWCDorjgrznjUStm9RcHeEH7MqXsrXJ+vUkJhRtLWqBLSuvCM\n" +
                "1577r/DK0SJavaE7FRnfF8S5mKMGzdXEHU3iKMQ6YNVZfB58FqFUg4twCzfgjiVi\n" +
                "WUJbJklqfPRI54kIoCqQDDtOjSm5EuXHaipeIduGrtOYwiw370rJTbb/BoPjkW56\n" +
                "aLk+nUyWjP+XcfPFMD8nzKT7mY1DJLiTYjqBQeXcj1tlnQpqg8vz4xSgRB4+0oJt\n" +
                "nmmiUSZl409UEgmVrGT7Kyyv4y01SjlcDWdUqq6ZMMNdgFVW+/OUCkQRBf28KFpr\n" +
                "E5ZtTWSw6KBRnjnXxAVDpYSIcX1Px1cU8Gwyi1wA6k5gT/lPGpylyAT6yhAI7XQe\n" +
                "n5nacdb2NSKeokudHnc5V6sPvjJemAxz+33PMmjpCWj4xVdPzeAZ8oOw2vVo6VKQ\n" +
                "Usnf0bF3ihYhBNGmbhojsYLJmA94jPv8yCoBXnMwAAA1cAv+LQ/CIFkB5rNaZWnB\n" +
                "3WCCWpa2BSadITA/XlF2fc9ZQgPfiiTCTEd17sy7Zbk3WcRqnNcmlMdx1FAv/hfP\n" +
                "q/Sg2MSWFNgw9SS1iLKUrLzRzVtAAYQqj6t7YETepjQ2WH/mH9PIQ6qDzSYVUZRs\n" +
                "ixKx3dDNzh2gQEShxeyfnELaP7FTUl0Molx9RCX3Q240lxLw2J9nm0DNW6V5oNFt\n" +
                "9zQ3o4QPKqzBpreVc8XkfLrmPUqcJh9zFrpmEqnZn2U5wmXfsB5EoOyENkQpYaxC\n" +
                "aSwooE3hyTI0eLIXuD9fR0MCCnL4gjKo9R556JjRKl6yn4+Y97GEOjat/DaHzz66\n" +
                "V/bO9yZIkt3QDnNnM0/TDJKTtGKJ9id4Bro4WyrNB6ICgEMrSBQcHHvt5GcEaxmF\n" +
                "2wqAQ+Qsh3WtUvYX0vBR16+CIiSjZehbDjov3yLTXB426L1DxFx7yDfwomvPhU2l\n" +
                "FbNZoOLjj+ZOBf1EvXxQW07iRCjwHzxBDQY4+K5l1OzgFLaE\n" +
                "=IqRH\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "Unknown subpacket in hashed area is not a problem.");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void primaryBindingCriticalUnknownSubpacketHashed() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJfarhYAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmd5hAoPaQrtdA/HBKZHkjhnFTKBFNIXmLAP\n" +
                "fbZ9NyFxxgMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAzKIL/iS7\n" +
                "Q7/5szuht5ilCHaE0c6R78YVqmQol4M4DgtRWfjatrYY1hD8lZuaYtAQhvGfG1Ez\n" +
                "uQrfFJGewPhsSFXyKYEOFEzLA6K2oTpb1JYzq0p1T+xLH+LJoPm/fP/bMKCKE3gn\n" +
                "6AT2zUaEgneeTt9OHZKv0Ie2u2+nrQL9b6jR2VkqOGOnEuWdBfdlUqqvN6QETTHG\n" +
                "r4mfJ+t7aREgcQX4NXg6n1YKA1Rc1vJWYQ/RyF1OtyxgenvJLpD1PWDyATT1B9Fo\n" +
                "hRzZrdX6iTL2SlBMzwNOfsphnFs2cqRMx3Iaha+5k0nqtbOBkYd02hueGhSSqTcb\n" +
                "5fnciAqwW5m+rjBqcXyc+RcmpSAqxNnNbi5K2geO2SnWD221QG5E1sAk1KBx48/N\n" +
                "Wh8obYlLavtET0+K28aWJern3jMeK93JIu4g8Kswdz5Zitw9qcTYcBmZfYTe+wdE\n" +
                "dMHWNtEYYL1VH8jQ9CZ+rygV5OMStyIc57UmrlP+jR4fDQDtBOWqI6uIfrSoRs7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCw0MEGAEKAncFgl9quFgJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ6hPh3OQRFaLZw6VyfpHQ7Zs\n" +
                "AAeGiGxGe5Z6tD9oU5BnApsCwUOgBBkBCgB2BYJfarhYCRB8L6pN+Tw3skcUAAAA\n" +
                "AAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmcicycMXxk2yzw4pRPl\n" +
                "rCBNsRIXo5HEnBxGtCKAaA36FhYhBB3c4V8JIXzuLzs3YHwvqk35PDeyBv92YWx1\n" +
                "ZQAAlc4MAKjJOktq6G67sylSA45Id6iA8RnzheQ9oU+BRsUg6ZjJ6f7PTHfrq9CS\n" +
                "GfOqXqjD0fwysxVSYViSrHe7uCZ7XPpiTlbfA8mCLkb0SG8jqVF3HFUQyQGBE5Wq\n" +
                "HoUSg/twJBSeNN481DAHMyQJDrqHWg7zmRKQwQiVD9U/NIuEgSH8nROjH04nw9VJ\n" +
                "RFbxtcqeQG6YN1t86jRTCSP0aRPXJZcaecaQ0bo1N31ScUmNfuPaAls2ejmuE6ax\n" +
                "0KYTrP3cCc8hDvHzzK1tjtaRCiXxQnxoJ8MquDRUWt2msBUvohMKfRd2SZfdskT+\n" +
                "iKGPH+GqaTEKv6s8NUlB5z6BLH3tU3bCJATdeF7u6R/Lqd6gLJvwwfwyvZovnrsM\n" +
                "mX51TrcbDTcMwU//UCXco2EPz7OxoSjfUU/4ybQ14layat1w83GWDisbsQAiY/Ln\n" +
                "N558HEhDoMBpQGwABXlWlOR8StKULoIxUsXlBHNtq4LHrvRzbIm5acRhJREC/YXk\n" +
                "eizz9u+neRYhBNGmbhojsYLJmA94jPv8yCoBXnMwAABudQv8CVeUGCJHoZrIONq8\n" +
                "d4BvS7iIbnvKvUFtx9JYC5Eziwrr2NNfh0UF2e7uml0T8QuMcliJUb3UARa63Fww\n" +
                "+05KJ1CtTkah9NeddxcIzOUdyVh9E7YVaBD1ktlIiWorFQqr+Xotfl5UqQAm/n+F\n" +
                "Xl8I9xUk3tSgVZOrljkcz3SnJY/9StQTijh227kKZTsQxTImvGpbdJjEB/334PJZ\n" +
                "+EebZiYnQpV1pgC8PseLs4SG/P7N/7ZkEsiUW4j6MJtZnkjMZCl2O0LjCSuS2JE3\n" +
                "HaQlCxRQ4RVKrxYMUKNi6FG7xpHYRn8KJZ5KueKMZ/NLG8IFQuzHun71SX1oOKzm\n" +
                "kBRaD97aiFwyWkE4pZIZh7M+Lqewq3lzX3oWYE2c+QdGezjDV2gOAFWiS4aA66VP\n" +
                "hIm3UrLh4KRX6CtosQobFFnF+hVYuZcLv1QY0OaRXIHWtEPsVeRcjoz46HzI8QJo\n" +
                "Qxj2LzcjT8J2nago6LeNcN5Vtn/1o6GKJQS/NxcZlMNAQMKm\n" +
                "=Pixl\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationFails(key, "Critical unknown subpacket in hashed area invalidates signature.");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void primaryBindingUnknownSubpacketUnhashed() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJffkFBAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmczJlC5YIwrzTzm6gIe+t+DikmEeomJlTxx\n" +
                "+qVzM4WwDwMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAJ5YMAINJ\n" +
                "nVggl0BxncDsXW3ZDKg4NKFIBDfDuGSq1Sk3g6fDd5hZP9scXcpgQvsTI8cHyJr4\n" +
                "jk6AHO/OHW8gpWvOEV7pamIp9EP1vn5ZgO0bCkZNXjKPq8a/xlFb00HSO34hV07i\n" +
                "wCnBuhyAVdxDlXWHb9CGjChcyt4CtyL8SA7OBu5USO8D01AGSX+US72ZQYT304pf\n" +
                "a+0vvrCM9vemXqT/NcppOtS0ZL9rL3VYrwxupPoPbLmbPZgewnEzB321d5fKStHb\n" +
                "+jHec0BiHSjVgwhbqhJ2vNfoa41X1SZhiFwvVYTTcqKsZtsZvNv2DISNGjj71A8s\n" +
                "BaBzAGkQuLII0QARGc8Uk8FpnSRHBCO9gjlOzIVQ5p0eZpmglJKqZBGVlxWIDio0\n" +
                "+qDpPz17nPsoXIyG8+OZyuRXsMByXTB1bCwBUwX5zD5PpFo1f9Zuh9iX7CGhltvE\n" +
                "mZsgstx1mjCHWdLFFvPcGCpQHJ1UxtT88Ag/h3f1UFUyhnkk3K4dcJYWsf3cPc7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCw0MEGAEKAncFgl9+QUEJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZyn+QXu5WbjSVCOYwSoDJKoa\n" +
                "dLGXoTeHOR5iXjLeM9chApsCwUOgBBkBCgBvBYJffkFBCRB8L6pN+Tw3skcUAAAA\n" +
                "AAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmfLXnyCoQwKmMYQpR3N\n" +
                "zzbq9q6YpG5hv9HUyzROJCykkxYhBB3c4V8JIXzuLzs3YHwvqk35PDeyAAcGf3Zh\n" +
                "bHVlgBYL/3VBXFEzMskZ7F81m6RmpFhBFWGRS/DRjBLxX9f8D+GO6Bod0VfBYWmF\n" +
                "QbTKPA5CT/q6+UBRywtlIU96FTslsEnbedHupjaCoBuVCJXl3E+EO2oiFZIXXg1r\n" +
                "zd4ZlNWEt1hF1lQc+MCyAzJmXxoMdSwCTEYTbxFRe8fsOWAhPfzfMd5D8Qge2dGe\n" +
                "4REWA3oEOcy9E1qYqvYaLojTs45Bog3OKQC8rJ2YAW8n0+G7ZFbTZT/dRYs4Ygzx\n" +
                "sb2aQ4qN2NbZWHJlLLIqM3jxZj8tviSEIfecv/ckB5PIWzjjaPueqT1jpEO2EteF\n" +
                "y1JjW3bcNzv8X0X9svqM+xz04cUtnmZjHQH6W6W9ADAxriVksC2Xjl38WCiuG2qN\n" +
                "8d9f8Se2whuc75/EOcUb1DWgoGcHNIFrB66FxDwFTQzPfJ4+F1VvWPQ5xq/KljOb\n" +
                "nsW9OnoHbKLwZ+EIDQa0pEamwrNg674NGSNK3oJ9DrKUZ8SvtO/ou0YXp0fd4c/9\n" +
                "2qTjSFwqchYhBNGmbhojsYLJmA94jPv8yCoBXnMwAABdrgwAuImuk4YBtCosyvUC\n" +
                "YFurpltYNbcDbsiQqPTr+2GLJfpeJ734jpie6hH87KqTQ8ghTEAu1XzYE5FcLRGn\n" +
                "a+twuslx2tFs0TMt4fCIIIjAPy5d/ziOa8M/ezWHjGi6QOwHNqrxmaa+MnLNSA6w\n" +
                "SCr9aaJZMwclsY/5Tf2SUPzAi1WX8vz0J316Aq+PjW9wukYnOQeKZmnkqPs866/3\n" +
                "M0tIQmtCuDib9osGh+KWPizy2cK3l4LEfAPfPtX8lV8kOtF2KD/B7SH/Qx/vx96B\n" +
                "bN7ryS4SNMCVbFwRF79Zy80Cwldhc70iBXxRfi8ocDVGB4oYm3TrMBUsbVIJVVji\n" +
                "hB1b0jMqaeo6ecOBQKrteeyl/QNuFrrnVO7wa2URuPMU+2VqXNZc+n95rWH1IO49\n" +
                "/MHgdefnVHCJH3/WE6yq1olx98DOxi6Ig7GBNdlOh8CeG8dkJH75we6wvfixTmT/\n" +
                "5dNfKXIieQI0zHMqeB5zDFGx1Dmki8G7U23BSklnIxuXbzNR\n" +
                "=SDad\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "Unknown subpacket is not an issue in the unhashed area");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void primaryBindingCriticalUnknownSubpacketUnhashed() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJffkFBAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmczJlC5YIwrzTzm6gIe+t+DikmEeomJlTxx\n" +
                "+qVzM4WwDwMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAJ5YMAINJ\n" +
                "nVggl0BxncDsXW3ZDKg4NKFIBDfDuGSq1Sk3g6fDd5hZP9scXcpgQvsTI8cHyJr4\n" +
                "jk6AHO/OHW8gpWvOEV7pamIp9EP1vn5ZgO0bCkZNXjKPq8a/xlFb00HSO34hV07i\n" +
                "wCnBuhyAVdxDlXWHb9CGjChcyt4CtyL8SA7OBu5USO8D01AGSX+US72ZQYT304pf\n" +
                "a+0vvrCM9vemXqT/NcppOtS0ZL9rL3VYrwxupPoPbLmbPZgewnEzB321d5fKStHb\n" +
                "+jHec0BiHSjVgwhbqhJ2vNfoa41X1SZhiFwvVYTTcqKsZtsZvNv2DISNGjj71A8s\n" +
                "BaBzAGkQuLII0QARGc8Uk8FpnSRHBCO9gjlOzIVQ5p0eZpmglJKqZBGVlxWIDio0\n" +
                "+qDpPz17nPsoXIyG8+OZyuRXsMByXTB1bCwBUwX5zD5PpFo1f9Zuh9iX7CGhltvE\n" +
                "mZsgstx1mjCHWdLFFvPcGCpQHJ1UxtT88Ag/h3f1UFUyhnkk3K4dcJYWsf3cPc7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCw0MEGAEKAncFgl9+QUEJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ70am+dYCWRwUzhaWg+3YPRH\n" +
                "ytwgKuy0xlIrTgd9FPJHApsCwUOgBBkBCgBvBYJffkFBCRB8L6pN+Tw3skcUAAAA\n" +
                "AAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmcIwr1qIkpRY2iNE6Fu\n" +
                "Lro2hiqHw066OasPdIGHIgiJtRYhBB3c4V8JIXzuLzs3YHwvqk35PDeyAAcG/3Zh\n" +
                "bHVls1ML/AjeKS6VlMxNjG460bKIu8tS0K4BLbdGRzzpsQGfYKTy/WuuXpo4IXzK\n" +
                "ZmF1wjBGuQ7YUoXNCtjeT9JaFmweZVyaUYFEJM0ut3hmo41hGHgO12wWQvjfv46y\n" +
                "V3QT4eFRByAkb0qxPsP5LkZ31ReOW0Ppi2KlAUSH405uiRxI2NJ9K5pN76jiKzH0\n" +
                "2u5dJSrQVUtXMr/so8gBY5Zs5KoNj/oaLFIG/yiYy1KOaGcJmMVxiSVWtN7Z2nYg\n" +
                "QsHKq6q8WRMLyeFiG7k49TtRPIvSHqdzZBG955him+OLzXlZvWgtvI42TwPpfZjJ\n" +
                "FJ/pkb5SlKVVs5VrFvaa/P0CP1Dhr2CqZRY09FrybrD1pc9MfOVKzozstLYTQnnz\n" +
                "S/Sz0mT0KEH2EmGbfqZ4p98FLCctnSkYgmDWLDuYK2Fx05PNhSTocMGzJ7uFVZdd\n" +
                "G4l37RVLFM0A2ifOAyc9jXN5CIoywmKUenO4WfguVL05cDxgpxcEmxIj7Kl1FlB6\n" +
                "Il1XjAAW0xYhBNGmbhojsYLJmA94jPv8yCoBXnMwAADKkQv/SSewTK0m/J0UqwhS\n" +
                "HpbGJEkikXLRJHlYdEOyudfBHnhiFyxTUtXPdnYqLDI8aQXQxMD1Tvs4YPplsm4K\n" +
                "b7RtEpvBQlcD7VK6da2InDt/IOl7vsnGsvwRL7uh5OFZZ3LkyE/79z2UZrtldFFZ\n" +
                "QrPk5X7Qlfol6F80NkEAY83wNMLU0IS20YTG5lawRYA5C9+JkihvS9vssFU4lmcd\n" +
                "GVvXFUP9y50MLzlFIlkZUwyZQ1xjvaz08nZBFJP1GONMHVxZWIjmsIlBfhVkTiqm\n" +
                "N4I+De1pD1cjp3mZb+gtDhHBe6wIJQFXlgDM4MHseYOr6WzjfZwfFRs0bTB0z3uR\n" +
                "JNbMM6bWAGgC/yLgQopoNulbjmxWjRSdwxtPvYsQC0AlUBrKLDOQhd6WDKidvFeG\n" +
                "q3hHXLwj34aKpbpXuQXQ2scZfe1C3+0laU5upQsvi95aIxyZav7Whde7TtWorm2t\n" +
                "4bL91n9Ffbco4yzGiVRx2/OP5+qnGrTVnAUkHfV7/E/FuOKi\n" +
                "=xogK\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "Critical unknown subpacket is acceptable in unhashed area of primary binding sig");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void primaryBindingUnknownNotationHashed() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJffkFBAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmczJlC5YIwrzTzm6gIe+t+DikmEeomJlTxx\n" +
                "+qVzM4WwDwMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAJ5YMAINJ\n" +
                "nVggl0BxncDsXW3ZDKg4NKFIBDfDuGSq1Sk3g6fDd5hZP9scXcpgQvsTI8cHyJr4\n" +
                "jk6AHO/OHW8gpWvOEV7pamIp9EP1vn5ZgO0bCkZNXjKPq8a/xlFb00HSO34hV07i\n" +
                "wCnBuhyAVdxDlXWHb9CGjChcyt4CtyL8SA7OBu5USO8D01AGSX+US72ZQYT304pf\n" +
                "a+0vvrCM9vemXqT/NcppOtS0ZL9rL3VYrwxupPoPbLmbPZgewnEzB321d5fKStHb\n" +
                "+jHec0BiHSjVgwhbqhJ2vNfoa41X1SZhiFwvVYTTcqKsZtsZvNv2DISNGjj71A8s\n" +
                "BaBzAGkQuLII0QARGc8Uk8FpnSRHBCO9gjlOzIVQ5p0eZpmglJKqZBGVlxWIDio0\n" +
                "+qDpPz17nPsoXIyG8+OZyuRXsMByXTB1bCwBUwX5zD5PpFo1f9Zuh9iX7CGhltvE\n" +
                "mZsgstx1mjCHWdLFFvPcGCpQHJ1UxtT88Ag/h3f1UFUyhnkk3K4dcJYWsf3cPc7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCw2gEGAEKApwFgl9+QUEJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZwYyHE0TL++fj0otGEGhkpSI\n" +
                "Iu8FqtiFLYoSb/tVrC48ApsCwWigBBkBCgCbBYJffkFBCRB8L6pN+Tw3sisUAAAA\n" +
                "AAAdAAV1bmtub3duQHRlc3RzLnNlcXVvaWEtcGdwLm9yZ3ZhbHVlRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ/ZJUjW/650Zi+XMhaJ9ZZ8R\n" +
                "wCz18pnNY6sqr8X1966gFiEEHdzhXwkhfO4vOzdgfC+qTfk8N7IAANEqC/9V9yqn\n" +
                "cjMFKUjXrRymSpfIy5QegGHTlhe700rKdxFyWPvbXxwnRiwyO/cly0Fb87No2two\n" +
                "m7+ozTWD0UOifNEF9VzCn+p8cT7+sAaQYscgky/RkFm3EnoLW0i9ieJlZ+KfDDB/\n" +
                "jHAvoEwUZ0RzhVIyO3yGgvpI25Wk5eeovU7azmAQ2Cj/B3o5dAx8PbPMvvGKxaF1\n" +
                "cSHQ2tEImfQkC5YxxDx2VrGEmVkKKiyFEYxUsSV6FKMw7K6tKEsRPY4tVaeZtcYo\n" +
                "QC22W/nZn9AxkuqqYptr8VL5ZhfpH8Dq0tvPfapjxKGl805nXRtzqtnhJILLovhV\n" +
                "Qt3ZdzzmqWiTt0cW375x2cq2UlYNPIQL/qum0+1rj+WNap7QSJ3DIWo3Igv3dhSk\n" +
                "GlyoXuD9++3M12O6shfT7CuBZdHmkwCdJDC9s5EuFOAyCBYb9nLnOhcj/edG3uEY\n" +
                "67fe/JLtQmv1L6HU6ewy4F01GPsDNN2z8AX3u0V1Km1YwZhdpBB/+l8sRmYWIQTR\n" +
                "pm4aI7GCyZgPeIz7/MgqAV5zMAAAU8cL/3/+rGuID3DOjqfA6HNoNsllkud1gjkC\n" +
                "9qoiB+T8OlDM0I1LNENrjtBfzwB4uuKxtqY0fdlBa8MPlJMRnZX83Ev7jAPl8PYS\n" +
                "3q3oK1I7ymjmBBNaZ1I7djIxDwecYn8A6r+uc2SwAD6G0sRy3rkUXHNEJGEcjwFf\n" +
                "3rbrI+7gWAVCY7qn6DNu2eNSRscV+GU/LQ3W+na4n6hIugd8yKCAPl4fKsZtU85S\n" +
                "UgLaUdQWoLJWcD54tSfmYZ0pRcQB85189Mo/gu6csBaz2M4a7GIc4+eXadtoJ72g\n" +
                "YcKOnHLFEPR2qkK/NqIoNR6aEfJ+ti3Kdua7jT31RfaiftB2Uj0wctpKItjOlCLS\n" +
                "NGSoaR2uvXg1pm+C3Rc395IaywciLfSKE42Dx6XK8TAcN+MGFVojsxeSFkm/PNIg\n" +
                "ELpz5C7mOTUCwbVA2UoDazSMXJN8calBUHwGjTf79G98NxE6zW1j3cr7+rPUqOAz\n" +
                "iShtvMX59VD5HBxeTZF+U22/cNIRcJ2eUA==\n" +
                "=nQN9\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "Unknown notation is acceptable in hashed area of primary binding sig.");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void primaryBindingCriticalUnknownNotationHashed() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJffkFBAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmczJlC5YIwrzTzm6gIe+t+DikmEeomJlTxx\n" +
                "+qVzM4WwDwMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAJ5YMAINJ\n" +
                "nVggl0BxncDsXW3ZDKg4NKFIBDfDuGSq1Sk3g6fDd5hZP9scXcpgQvsTI8cHyJr4\n" +
                "jk6AHO/OHW8gpWvOEV7pamIp9EP1vn5ZgO0bCkZNXjKPq8a/xlFb00HSO34hV07i\n" +
                "wCnBuhyAVdxDlXWHb9CGjChcyt4CtyL8SA7OBu5USO8D01AGSX+US72ZQYT304pf\n" +
                "a+0vvrCM9vemXqT/NcppOtS0ZL9rL3VYrwxupPoPbLmbPZgewnEzB321d5fKStHb\n" +
                "+jHec0BiHSjVgwhbqhJ2vNfoa41X1SZhiFwvVYTTcqKsZtsZvNv2DISNGjj71A8s\n" +
                "BaBzAGkQuLII0QARGc8Uk8FpnSRHBCO9gjlOzIVQ5p0eZpmglJKqZBGVlxWIDio0\n" +
                "+qDpPz17nPsoXIyG8+OZyuRXsMByXTB1bCwBUwX5zD5PpFo1f9Zuh9iX7CGhltvE\n" +
                "mZsgstx1mjCHWdLFFvPcGCpQHJ1UxtT88Ag/h3f1UFUyhnkk3K4dcJYWsf3cPc7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCw2gEGAEKApwFgl9+QUEJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ+YQ9A1f4N1bYZNKumNsSQb3\n" +
                "cr3HErC8EfLoT7wWJK6OApsCwWigBBkBCgCbBYJffkFBCRB8L6pN+Tw3siuUAAAA\n" +
                "AAAdAAV1bmtub3duQHRlc3RzLnNlcXVvaWEtcGdwLm9yZ3ZhbHVlRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ2j36YpkuUuxxUBY2kIAFiKA\n" +
                "xBS9L2H4g8W85T1MuJguFiEEHdzhXwkhfO4vOzdgfC+qTfk8N7IAAA0sDACbc557\n" +
                "KAGoIFSf5x7rgJ31dpjKqJyHHmki0CN6bqW0qSLiFVUm0O7pqLWZW3V5AZMWVVtF\n" +
                "zlAs6sgVdhLxC2OIfNiD6OZUysAtHKLwxGNCp0tDxhhiUC4iuE89s4YZ0skGqs/k\n" +
                "erDN/5HRVqF3IWhXHA7OogLsQRGbpMPzOqeGcrQRHp+EqnfYO2vQcXIjDg69E6wQ\n" +
                "mzbt3W59D6uJJ0mMjANCm239xUCDonoi+hgmGtLNHbJRC58UhyP3JUBmX/IDYG0A\n" +
                "ISpvgXgi7xRz2JgnIv1fqqh4rEttTSKjSbSqUmf9eQLU/hfmSMbtIDCZH+PTnRRf\n" +
                "ye7X2ab/6i4w62MT/aWiin45u8s6kG6+0AbiLVebTL7rddagLI/lxegFpCEcV5H0\n" +
                "Xf4KgpGJL2zZgIAJ0lKzkSoFcYlUUiBg+DGh3YK9nnyrVtK5pB2tRVRvPUbnPEqj\n" +
                "kO37EH8E8pdP3gnOUamPWgazAupHFgSOjNM0pVvUrlIH4mI/1iyCC7DA+joWIQTR\n" +
                "pm4aI7GCyZgPeIz7/MgqAV5zMAAAaTAL/2bY9eKZLsLVNUGV5NZQ5vEoUOcjTAlO\n" +
                "pG3nxtzODY+lnVxfgLcb9jvuWxWz0PnYLBm2qnqoAYqJOt1yRVfQFKZAxEWvtZgB\n" +
                "LWZcNIY2/NC3Fy98of7djViD5nHktl2vTOLyRnutqgD8EfviBZqjy6UF12mL08nJ\n" +
                "MniAkZtVCgHk1j/HEtXrASO1PWfzVSOew6Jtq6RWfWzhGBHgLqoEsvofYxQnU83F\n" +
                "A8IQ6P4GULMxZeboWq1sKyIjKKzoU3crHEdWoIPWuyWKMy5DCuuEda5q5aFGZfWd\n" +
                "c+6zwUGNPbecXM4eNvOPeUrtcnZTj0gFpdsutCp59lWd4XkOfqhVgGiqeexZ+Q6H\n" +
                "BWp3LTvEo/amrmGq0O4SbCquyap9g8D/g7hh9K7JrREfhHJ9Mp0Ql8VZ6LOIlmQR\n" +
                "RV42SzORUrJpJgPviUMSUH27hOVidymUsJkkInktL+IKNCvDnTNm+hoXmMuyQA9r\n" +
                "FAOuVlKPStWFgQ1NVsqFzthAcJUp2IxCWw==\n" +
                "=fxEe\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationFails(key, "Critical unknown notation in hashed area invalidates primary binding sig");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void primaryBindingUnknownNotationUnhashed() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJffkFBAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmczJlC5YIwrzTzm6gIe+t+DikmEeomJlTxx\n" +
                "+qVzM4WwDwMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAJ5YMAINJ\n" +
                "nVggl0BxncDsXW3ZDKg4NKFIBDfDuGSq1Sk3g6fDd5hZP9scXcpgQvsTI8cHyJr4\n" +
                "jk6AHO/OHW8gpWvOEV7pamIp9EP1vn5ZgO0bCkZNXjKPq8a/xlFb00HSO34hV07i\n" +
                "wCnBuhyAVdxDlXWHb9CGjChcyt4CtyL8SA7OBu5USO8D01AGSX+US72ZQYT304pf\n" +
                "a+0vvrCM9vemXqT/NcppOtS0ZL9rL3VYrwxupPoPbLmbPZgewnEzB321d5fKStHb\n" +
                "+jHec0BiHSjVgwhbqhJ2vNfoa41X1SZhiFwvVYTTcqKsZtsZvNv2DISNGjj71A8s\n" +
                "BaBzAGkQuLII0QARGc8Uk8FpnSRHBCO9gjlOzIVQ5p0eZpmglJKqZBGVlxWIDio0\n" +
                "+qDpPz17nPsoXIyG8+OZyuRXsMByXTB1bCwBUwX5zD5PpFo1f9Zuh9iX7CGhltvE\n" +
                "mZsgstx1mjCHWdLFFvPcGCpQHJ1UxtT88Ag/h3f1UFUyhnkk3K4dcJYWsf3cPc7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCw2gEGAEKApwFgl9+QUEJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZwBFME75y8sQFn1PwmOCDkJc\n" +
                "e+TNcZD7kXPBEGV75gvyApsCwWigBBkBCgBvBYJffkFBCRB8L6pN+Tw3skcUAAAA\n" +
                "AAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmfZqaBfsBdflaWMtURV\n" +
                "I0vkApvwQRIGwy3VQ1May0E/ohYhBB3c4V8JIXzuLzs3YHwvqk35PDeyACwrFAAA\n" +
                "AAAAHQAFdW5rbm93bkB0ZXN0cy5zZXF1b2lhLXBncC5vcmd2YWx1Zf8VC/9h49l4\n" +
                "xDe19CqkL5+8yu20xn9kwikZZB4uqrUjCE1I67eTl9UQYMKTIK7u4Leo6vUVHHyy\n" +
                "P9kMF4rHOYjfsQj5NLa+v7ihKKzS9ePPt3fugJJnAYpSJ6WoCUa7q27VK820WPnR\n" +
                "U790o6R6/xptHQ5KpSSYSXCF7fL49/VoSgZ7fQ895mhQLV/6RxWIczrSNvpb4ONE\n" +
                "B8sxzF99IZA3qqltvhjseOvGpjZ//pzOvY0MU17Wy7OQ/c7Ywm/wRnVIEHGn/axU\n" +
                "51t9rk/z1x6F6QZ+pFC4iSU1TtC9Bmw6qJmMPT7YfkYnCXHZBlUq3GxigPviVcv0\n" +
                "DG97o905GlOWhH83yP/j7XAstGEA/GIkztSsUhlz+VgfsAoHxfdHvJ0oAlafMbAF\n" +
                "SmY1FnZoo1Urq256nvp90ewuFklJM+S5Fq272f9CtcqtDgh2PA1oCCQjU906Vkhv\n" +
                "uYWwzKIOnzKyJfE607C9ANKLb4jvIk6lb00SS0SBghiX/qrbqpDSaqG9+8gWIQTR\n" +
                "pm4aI7GCyZgPeIz7/MgqAV5zMAAALwYMAKvQnX+ThfhZuxxE2Or8l1Zg5i92WLEn\n" +
                "IUeT8Z0Sks1LtbddcF4Rg8UQeHfWyiOoPiVARxxQgZwpBDNMs4vFOIbjAW9mitTB\n" +
                "pV26R90JOldPCjJzR0FMUV6rIoYkXnxSD8qMahApZ4DPZ0FaHpZ6NugzKwE7ZYqR\n" +
                "cd7Ae7cTLb9nrfJQ1Sf9bxMvuYiniKwCL92iqo1rntnJELylu45PimS9wfse95A9\n" +
                "6QTQxx2PXjh2BF+XcHm6/fYv5e2I1K+OxPwI2rUJF39kxue4fErlNkIdMuV5JWZO\n" +
                "vQYb6FEVPKdbpPp0iXJqEkdpgvaMMAiuvXQwpzxMWaVsrOOPT+EZTXO6JrI7OW1+\n" +
                "JD0ffK4SAv4Z9/hIbivkjYc23jq7GNlJSi5E1jpyf4Jra9nmWzboTz7v2BcEvB9U\n" +
                "UFf52KA1fDUOmfSm+tTMJNh0yPA+VOfbnwpf3qpUczMO/U9GD4XeHG+FWV+CyrsT\n" +
                "NxBszEsvsO6SrcdWYYLyIlHmlIqpuSYVHg==\n" +
                "=CcRZ\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "Unknown notation in unhashed area of primary key binding is okay.");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void primaryBindingCriticalUnknownNotationUnhashed() throws IOException {

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
                "bGU+wsFIBBMBCgB8BYJffkFBAgsJCRD7/MgqAV5zMEcUAAAAAAAeACBzYWx0QG5v\n" +
                "dGF0aW9ucy5zZXF1b2lhLXBncC5vcmczJlC5YIwrzTzm6gIe+t+DikmEeomJlTxx\n" +
                "+qVzM4WwDwMVCAoCmwECHgEWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAAAJ5YMAINJ\n" +
                "nVggl0BxncDsXW3ZDKg4NKFIBDfDuGSq1Sk3g6fDd5hZP9scXcpgQvsTI8cHyJr4\n" +
                "jk6AHO/OHW8gpWvOEV7pamIp9EP1vn5ZgO0bCkZNXjKPq8a/xlFb00HSO34hV07i\n" +
                "wCnBuhyAVdxDlXWHb9CGjChcyt4CtyL8SA7OBu5USO8D01AGSX+US72ZQYT304pf\n" +
                "a+0vvrCM9vemXqT/NcppOtS0ZL9rL3VYrwxupPoPbLmbPZgewnEzB321d5fKStHb\n" +
                "+jHec0BiHSjVgwhbqhJ2vNfoa41X1SZhiFwvVYTTcqKsZtsZvNv2DISNGjj71A8s\n" +
                "BaBzAGkQuLII0QARGc8Uk8FpnSRHBCO9gjlOzIVQ5p0eZpmglJKqZBGVlxWIDio0\n" +
                "+qDpPz17nPsoXIyG8+OZyuRXsMByXTB1bCwBUwX5zD5PpFo1f9Zuh9iX7CGhltvE\n" +
                "mZsgstx1mjCHWdLFFvPcGCpQHJ1UxtT88Ag/h3f1UFUyhnkk3K4dcJYWsf3cPc7A\n" +
                "zQRdpZzyAQwA1jC/XGxjK6ddgrRfW9j+s/U00++EvIsgTs2kr3Rg0GP7FLWV0YNt\n" +
                "R1mpl55/bEl7yAxCDTkOgPUMXcaKlnQh6zrlt6H53mF6Bvs3inOHQvOsGtU0dqvb\n" +
                "1vkTF0juLiJgPlM7pWv+pNQ6IA39vKoQsTMBv4v5vYNXP9GgKbg8inUNT17BxzZY\n" +
                "Hfw5+q63ectgDm2on1e8CIRCZ76oBVwzdkVxoy3gjh1eENlk2D4P0uJNZzF1Q8GV\n" +
                "67yLANGMCDICE/OkWn6daipYDzW4iJQtYPUWP4hWhjdm+CK+hg6IQUEn2Vtvi16D\n" +
                "2blRP8BpUNNa4fNuylWVuJV76rIHvsLZ1pbM3LHpRgE8s6jivS3Rz3WRs0TmWCNn\n" +
                "vHPqWizQ3VTy+r3UQVJ5AmhJDrZdZq9iaUIuZ01PoE1+CHiJwuxPtWvVAxf2POcm\n" +
                "1M/F1fK1J0e+lKlQuyonTXqXR22Y41wrfP2aPk3nPSTW2DUAf3vRMZg57ZpRxLEh\n" +
                "EMxcM4/LMR+PABEBAAHCw2gEGAEKApwFgl9+QUEJEPv8yCoBXnMwRxQAAAAAAB4A\n" +
                "IHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ2JRzdjMWDYQtr2T/dLwEDXN\n" +
                "l9wkz0jXF3AKqVhx2ivFApsCwWigBBkBCgBvBYJffkFBCRB8L6pN+Tw3skcUAAAA\n" +
                "AAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmfrCrBTMGW6X4ITei21\n" +
                "w9xjztPLbhSlEhfXilfL02q65xYhBB3c4V8JIXzuLzs3YHwvqk35PDeyACwrlAAA\n" +
                "AAAAHQAFdW5rbm93bkB0ZXN0cy5zZXF1b2lhLXBncC5vcmd2YWx1ZRYdDACFFQuM\n" +
                "JlVgqgk2PLO9ONzxq1sPgE1s06P5cg+tmIpI0RhjywmdgdaGmO4RXDczLS761FoX\n" +
                "mMS+4AJhygHpJPDb1kjlEb/v/COioMR0tkkOmz8UqZx46fT2nGK+MMhYv13P2oKL\n" +
                "rpotnB/fIBKmsA5cr/QcTG/XWTHvS4/jbp0RZIHuubgfLSQ5wOQedW3AsR2bRUAw\n" +
                "RcxeRFQVU03ndleN6r+UzKV8D0rHTnERKcxbWab+WA7/cgLdIiStTfRlhlTs+Ksp\n" +
                "mIQz4Tc/FrSFxZFSmiqcWbrN9CG7GE9jXxNkzyIsAww6eUqn2nRKWHQJtn0YK3KY\n" +
                "eMYIpskvnwCXMjdCEzzP+mVcniZ4zzzt+IfhTFcXCg0PyRBwkWEAUPxI8DALBf6k\n" +
                "f0k74BV6eOujq56//1rAodZUW45kQEA+Mgmf9ySONjdSv+KOtHnqwu/B/TGtqiuD\n" +
                "yohxrIbiMlWrXVzTzsEh6vfRDdpOOHcYWDnl4ZfzxCXjD2kHEHnQWPe2dGIWIQTR\n" +
                "pm4aI7GCyZgPeIz7/MgqAV5zMAAAqk0L/RxPWSjK8cLmEinDA2Br/ari5OLTMJaV\n" +
                "wEt0Bju5ccUuH/xkWxsAhjG3SYBAID5mbPAKb6pkkG33mApgxlyD4Jv5VbkxZ5xg\n" +
                "Dc03B6B9iK5u3Q8uCoWdwaMmI15G0b+Rg8DXRSph80yPRV7sQqdap+/EI8J20j15\n" +
                "zPz6YrzENzNrsl/Z7X/W3T7TFT3CasfndAHRdSRQUmDE9m22Vouj+xRZWB4NCPHN\n" +
                "nG2aDVR8g1UoodydEOEqYnDqcs9XvY+tyZXspNxn+a7pp24lpynn5OfJR6IGOUYM\n" +
                "UOIX+M9UDPlbVAAaV/I4RJkT1kafh0yTPtDewsEJ3xV31Uk7N+82+v5tKKPWQ/YM\n" +
                "05xiIwbj/nfcAz2ujJBULnw03CQ9OzGDQPNRTcd1sCwDDJ3gwl/xmPbfNZKYfkmK\n" +
                "xQQ/pQZC+HLdsDqmH8jhAVYiH4V1Ajk1DQR5v0/j6lfqZLfHauLx/LCzt7+K9DRQ\n" +
                "3ADU//ZKT2HDol0IEGiTgrGH4jyKBviurg==\n" +
                "=nAET\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";
        expectSignatureValidationSucceeds(key, "Critical unknown notation is acceptable in unhashed area of primary key binding sig.");
    }

    private void expectSignatureValidationSucceeds(String key, String message) throws IOException {
        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(key);
        PGPSignature signature = SignatureUtils.readSignatures(sig).get(0);

        try {
            CertificateValidator.validateCertificateAndVerifyUninitializedSignature(signature, getSignedData(data), publicKeys, policy, validationDate);
        } catch (SignatureValidationException e) {
            // CHECKSTYLE:OFF
            e.printStackTrace();
            // CHECKSTYLE:ON
            fail(message + ": " + e.getMessage());
        }
    }

    private void expectSignatureValidationFails(String key, String message) throws IOException {
        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(key);
        PGPSignature signature = SignatureUtils.readSignatures(sig).get(0);

        assertThrows(SignatureValidationException.class, () ->
                        CertificateValidator.validateCertificateAndVerifyUninitializedSignature(
                                signature, getSignedData(data), publicKeys, policy, validationDate),
                message);
    }

    private static InputStream getSignedData(String data) {
        return new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
    }
}
