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
package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.protection.SecretKeyRingProtector;

public class ModificationDetectionTests {

    private static final String keyAscii = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: Bob's OpenPGP Transferable Secret Key\n" +
            "\n" +
            "lQVYBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
            "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
            "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
            "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
            "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
            "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
            "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
            "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
            "vLIwa3T4CyshfT0AEQEAAQAL/RZqbJW2IqQDCnJi4Ozm++gPqBPiX1RhTWSjwxfM\n" +
            "cJKUZfzLj414rMKm6Jh1cwwGY9jekROhB9WmwaaKT8HtcIgrZNAlYzANGRCM4TLK\n" +
            "3VskxfSwKKna8l+s+mZglqbAjUg3wmFuf9Tj2xcUZYmyRm1DEmcN2ZzpvRtHgX7z\n" +
            "Wn1mAKUlSDJZSQks0zjuMNbupcpyJokdlkUg2+wBznBOTKzgMxVNC9b2g5/tMPUs\n" +
            "hGGWmF1UH+7AHMTaS6dlmr2ZBIyogdnfUqdNg5sZwsxSNrbglKP4sqe7X61uEAIQ\n" +
            "bD7rT3LonLbhkrj3I8wilUD8usIwt5IecoHhd9HziqZjRCc1BUBkboUEoyedbDV4\n" +
            "i4qfsFZ6CEWoLuD5pW7dEp0M+WeuHXO164Rc+LnH6i1VQrpb1Okl4qO6ejIpIjBI\n" +
            "1t3GshtUu/mwGBBxs60KBX5g77mFQ9lLCRj8lSYqOsHRKBhUp4qM869VA+fD0BRP\n" +
            "fqPT0I9IH4Oa/A3jYJcg622GwQYA1LhnP208Waf6PkQSJ6kyr8ymY1yVh9VBE/g6\n" +
            "fRDYA+pkqKnw9wfH2Qho3ysAA+OmVOX8Hldg+Pc0Zs0e5pCavb0En8iFLvTA0Q2E\n" +
            "LR5rLue9uD7aFuKFU/VdcddY9Ww/vo4k5p/tVGp7F8RYCFn9rSjIWbfvvZi1q5Tx\n" +
            "+akoZbga+4qQ4WYzB/obdX6SCmi6BndcQ1QdjCCQU6gpYx0MddVERbIp9+2SXDyL\n" +
            "hpxjSyz+RGsZi/9UAshT4txP4+MZBgDfK3ZqtW+h2/eMRxkANqOJpxSjMyLO/FXN\n" +
            "WxzTDYeWtHNYiAlOwlQZEPOydZFty9IVzzNFQCIUCGjQ/nNyhw7adSgUk3+BXEx/\n" +
            "MyJPYY0BYuhLxLYcrfQ9nrhaVKxRJj25SVHj2ASsiwGJRZW4CC3uw40OYxfKEvNC\n" +
            "mer/VxM3kg8qqGf9KUzJ1dVdAvjyx2Hz6jY2qWCyRQ6IMjWHyd43C4r3jxooYKUC\n" +
            "YnstRQyb/gCSKahveSEjo07CiXMr88UGALwzEr3npFAsPW3osGaFLj49y1oRe11E\n" +
            "he9gCHFm+fuzbXrWmdPjYU5/ZdqdojzDqfu4ThfnipknpVUM1o6MQqkjM896FHm8\n" +
            "zbKVFSMhEP6DPHSCexMFrrSgN03PdwHTO6iBaIBBFqmGY01tmJ03SxvSpiBPON9P\n" +
            "NVvy/6UZFedTq8A07OUAxO62YUSNtT5pmK2vzs3SAZJmbFbMh+NN204TRI72GlqT\n" +
            "t5hcfkuv8hrmwPS/ZR6q312mKQ6w/1pqO9qitCFCb2IgQmFiYmFnZSA8Ym9iQG9w\n" +
            "ZW5wZ3AuZXhhbXBsZT6JAc4EEwEKADgCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgEC\n" +
            "F4AWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAUCXaWe+gAKCRD7/MgqAV5zMG9sC/9U\n" +
            "2T3RrqEbw533FPNfEflhEVRIZ8gDXKM8hU6cqqEzCmzZT6xYTe6sv4y+PJBGXJFX\n" +
            "yhj0g6FDkSyboM5litOcTupURObVqMgA/Y4UKERznm4fzzH9qek85c4ljtLyNufe\n" +
            "doL2pp3vkGtn7eD0QFRaLLmnxPKQ/TlZKdLE1G3u8Uot8QHicaR6GnAdc5UXQJE3\n" +
            "BiV7jZuDyWmZ1cUNwJkKL6oRtp+ZNDOQCrLNLecKHcgCqrpjSQG5oouba1I1Q6Vl\n" +
            "sP44dhA1nkmLHtxlTOzpeHj4jnk1FaXmyasurrrI5CgU/L2Oi39DGKTH/A/cywDN\n" +
            "4ZplIQ9zR8enkbXquUZvFDe+Xz+6xRXtb5MwQyWODB3nHw85HocLwRoIN9WdQEI+\n" +
            "L8a/56AuOwhs8llkSuiITjR7r9SgKJC2WlAHl7E8lhJ3VDW3ELC56KH308d6mwOG\n" +
            "ZRAqIAKzM1T5FGjMBhq7ZV0eqdEntBh3EcOIfj2M8rg1MzJv+0mHZOIjByawikad\n" +
            "BVgEXaWc8gEMANYwv1xsYyunXYK0X1vY/rP1NNPvhLyLIE7NpK90YNBj+xS1ldGD\n" +
            "bUdZqZeef2xJe8gMQg05DoD1DF3GipZ0Ies65beh+d5hegb7N4pzh0LzrBrVNHar\n" +
            "29b5ExdI7i4iYD5TO6Vr/qTUOiAN/byqELEzAb+L+b2DVz/RoCm4PIp1DU9ewcc2\n" +
            "WB38Ofqut3nLYA5tqJ9XvAiEQme+qAVcM3ZFcaMt4I4dXhDZZNg+D9LiTWcxdUPB\n" +
            "leu8iwDRjAgyAhPzpFp+nWoqWA81uIiULWD1Fj+IVoY3ZvgivoYOiEFBJ9lbb4te\n" +
            "g9m5UT/AaVDTWuHzbspVlbiVe+qyB77C2daWzNyx6UYBPLOo4r0t0c91kbNE5lgj\n" +
            "Z7xz6los0N1U8vq91EFSeQJoSQ62XWavYmlCLmdNT6BNfgh4icLsT7Vr1QMX9jzn\n" +
            "JtTPxdXytSdHvpSpULsqJ016l0dtmONcK3z9mj5N5z0k1tg1AH970TGYOe2aUcSx\n" +
            "IRDMXDOPyzEfjwARAQABAAv9F2CwsjS+Sjh1M1vegJbZjei4gF1HHpEM0K0PSXsp\n" +
            "SfVvpR4AoSJ4He6CXSMWg0ot8XKtDuZoV9jnJaES5UL9pMAD7JwIOqZm/DYVJM5h\n" +
            "OASCh1c356/wSbFbzRHPtUdZO9Q30WFNJM5pHbCJPjtNoRmRGkf71RxtvHBzy7np\n" +
            "Ga+W6U/NVKHw0i0CYwMI0YlKDakYW3Pm+QL+gHZFvngGweTod0f9l2VLLAmeQR/c\n" +
            "+EZs7lNumhuZ8mXcwhUc9JQIhOkpO+wreDysEFkAcsKbkQP3UDUsA1gFx9pbMzT0\n" +
            "tr1oZq2a4QBtxShHzP/ph7KLpN+6qtjks3xB/yjTgaGmtrwM8tSe0wD1RwXS+/1o\n" +
            "BHpXTnQ7TfeOGUAu4KCoOQLv6ELpKWbRBLWuiPwMdbGpvVFALO8+kvKAg9/r+/ny\n" +
            "zM2GQHY+J3Jh5JxPiJnHfXNZjIKLbFbIPdSKNyJBuazXW8xIa//mEHMI5OcvsZBK\n" +
            "clAIp7LXzjEjKXIwHwDcTn9pBgDpdOKTHOtJ3JUKx0rWVsDH6wq6iKV/FTVSY5jl\n" +
            "zN+puOEsskF1Lfxn9JsJihAVO3yNsp6RvkKtyNlFazaCVKtDAmkjoh60XNxcNRqr\n" +
            "gCnwdpbgdHP6v/hvZY54ZaJjz6L2e8unNEkYLxDt8cmAyGPgH2XgL7giHIp9jrsQ\n" +
            "aS381gnYwNX6wE1aEikgtY91nqJjwPlibF9avSyYQoMtEqM/1UjTjB2KdD/MitK5\n" +
            "fP0VpvuXpNYZedmyq4UOMwdkiNMGAOrfmOeT0olgLrTMT5H97Cn3Yxbk13uXHNu/\n" +
            "ZUZZNe8s+QtuLfUlKAJtLEUutN33TlWQY522FV0m17S+b80xJib3yZVJteVurrh5\n" +
            "HSWHAM+zghQAvCesg5CLXa2dNMkTCmZKgCBvfDLZuZbjFwnwCI6u/NhOY9egKuUf\n" +
            "SA/je/RXaT8m5VxLYMxwqQXKApzD87fv0tLPlVIEvjEsaf992tFEFSNPcG1l/jpd\n" +
            "5AVXw6kKuf85UkJtYR1x2MkQDrqY1QX/XMw00kt8y9kMZUre19aCArcmor+hDhRJ\n" +
            "E3Gt4QJrD9z/bICESw4b4z2DbgD/Xz9IXsA/r9cKiM1h5QMtXvuhyfVeM01enhxM\n" +
            "GbOH3gjqqGNKysx0UODGEwr6AV9hAd8RWXMchJLaExK9J5SRawSg671ObAU24SdY\n" +
            "vMQ9Z4kAQ2+1ReUZzf3ogSMRZtMT+d18gT6L90/y+APZIaoArLPhebIAGq39HLmJ\n" +
            "26x3z0WAgrpA1kNsjXEXkoiZGPLKIGoe3hqJAbYEGAEKACAWIQTRpm4aI7GCyZgP\n" +
            "eIz7/MgqAV5zMAUCXaWc8gIbDAAKCRD7/MgqAV5zMOn/C/9ugt+HZIwX308zI+QX\n" +
            "c5vDLReuzmJ3ieE0DMO/uNSC+K1XEioSIZP91HeZJ2kbT9nn9fuReuoff0T0Dief\n" +
            "rbwcIQQHFFkrqSp1K3VWmUGp2JrUsXFVdjy/fkBIjTd7c5boWljv/6wAsSfiv2V0\n" +
            "JSM8EFU6TYXxswGjFVfc6X97tJNeIrXL+mpSmPPqy2bztcCCHkWS5lNLWQw+R7Vg\n" +
            "71Fe6yBSNVrqC2/imYG2J9zlowjx1XU63Wdgqp2Wxt0l8OmsB/W80S1fRF5G4SDH\n" +
            "s9HXglXXqPsBRZJYfP+VStm9L5P/sKjCcX6WtZR7yS6G8zj/X767MLK/djANvpPd\n" +
            "NVniEke6hM3CNBXYPAMhQBMWhCulcoz+0lxi8L34rMN+Dsbma96psdUrn7uLaB91\n" +
            "6we0CTfF8qqm7BsVAgalon/UUiuMY80U3ueoj3okiSTiHIjD/YtpXSPioC8nMng7\n" +
            "xqAY9Bwizt4FWgXuLm1a4+So4V9j1TRCXd12Uc2l2RNmgDE=\n" +
            "=miES\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestUtil#provideImplementationFactories")
    public void testMissingMDC(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        String message = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wcDMA3wvqk35PDeyAQwAnTmchA6ve/aF7cPEnyJSb9Ot61LSIMrU3+RaEdA90qn4\n" +
                "iC+yA7rH+nBX4t9nYSLI4EbQibSfzgxj0Bon1sAwfUfU88UMHypnL1HYsZRoiiLe\n" +
                "crRr/9Vot2X1firhSu6kwqPZw5eIbvPPhHojZxWo7Plv7lDsXdtgRXc544jKA+Cx\n" +
                "4Rt9D0WG7sWDifHUaitNHC4klZbvO29qmaND1F+RNUpO6H1j63UCPvHqSEvfV+kT\n" +
                "vQXtOqk34SLo8SOfpni8Dy1wUePIbuaXyqe5uwSprWoAAmRZOjskv6z28pj9jVs3\n" +
                "dWRkWca5Mmm3VQZlmxcNeFyTAgSth0GNalwWSVNcPK9W/VaDX8ecw7xYU04cpbQr\n" +
                "a4JF9oc33bhgn4ZDdcvcP8/QUQP+TyN4vGjp1k9+AgkIsJjLanqHE29chsh7ZcVF\n" +
                "GDjq3DppEo/Hh647rYRqXpxLfJB6fsDyYLmqNKsBcgtBqE9DtiXQ16GuGFrePxd2\n" +
                "nRKcSWQbisEa1LHr8G4d0jYBMjIoPiEhw4sgEt1ZCiQPO1HXqaK7VN3PhPOqjyjf\n" +
                "Rt6lN5kVA3+Dd2DRov9NQ83TQPJdg7I=\n" +
                "=pgX9\n" +
                "-----END PGP MESSAGE-----\n";

        PGPSecretKeyRingCollection secretKeyRings = getDecryptionKey();

        InputStream in = new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .decryptWith(SecretKeyRingProtector.unprotectedKeys(), secretKeyRings)
                .doNotVerify()
                .build();

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        assertThrows(EOFException.class, () -> {
            Streams.pipeAll(decryptionStream, outputStream);
            decryptionStream.close();
        });
    }

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestUtil#provideImplementationFactories")
    public void tamperedCiphertextTest(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        String message = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wcDMA3wvqk35PDeyAQwAnTmchA6ve/aF7cPEnyJSb9Ot61LSIMrU3+RaEdA90qn4\n" +
                "iC+yA7rH+nBX4t9nYSLI4EbQibSfzgxj0Bon1sAwfUfU88UMHypnL1HYsZRoiiLe\n" +
                "crRr/9Vot2X1firhSu6kwqPZw5eIbvPPhHojZxWo7Plv7lDsXdtgRXc544jKA+Cx\n" +
                "4Rt9D0WG7sWDifHUaitNHC4klZbvO29qmaND1F+RNUpO6H1j63UCPvHqSEvfV+kT\n" +
                "vQXtOqk34SLo8SOfpni8Dy1wUePIbuaXyqe5uwSprWoAAmRZOjskv6z28pj9jVs3\n" +
                "dWRkWca5Mmm3VQZlmxcNeFyTAgSth0GNalwWSVNcPK9W/VaDX8ecw7xYU04cpbQr\n" +
                "a4JF9oc33bhgn4ZDdcvcP8/QUQP+TyN4vGjp1k9+AgkIsJjLanqHE29chsh7ZcVF\n" +
                "GDjq3DppEo/Hh647rYRqXpxLfJB6fsDyYLmqNKsBcgtBqE9DtiXQ16GuGFrePxd2\n" +
                "nRKcSWQbisEa1LHr8G4d0kwBMjIoPiEhw4sgEt1ZCiQPO1HXqaK7VN3PhPOqjyjf\n" +
                "Rt6lN5kVA3+Dd2DRov9NQ83TQPJdgwCD5cXqlEliiMR4G0gWh8QZ4oAp541H\n" +
                "=wx2s\n" +
                "-----END PGP MESSAGE-----\n";

        ByteArrayInputStream in = new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .decryptWith(getDecryptionKey())
                .doNotVerify()
                .build();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        assertThrows(IOException.class, decryptionStream::close);
    }

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestUtil#provideImplementationFactories")
    public void tamperedMDCTest(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        String message = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wcDMA3wvqk35PDeyAQwAnTmchA6ve/aF7cPEnyJSb9Ot61LSIMrU3+RaEdA90qn4\n" +
                "iC+yA7rH+nBX4t9nYSLI4EbQibSfzgxj0Bon1sAwfUfU88UMHypnL1HYsZRoiiLe\n" +
                "crRr/9Vot2X1firhSu6kwqPZw5eIbvPPhHojZxWo7Plv7lDsXdtgRXc544jKA+Cx\n" +
                "4Rt9D0WG7sWDifHUaitNHC4klZbvO29qmaND1F+RNUpO6H1j63UCPvHqSEvfV+kT\n" +
                "vQXtOqk34SLo8SOfpni8Dy1wUePIbuaXyqe5uwSprWoAAmRZOjskv6z28pj9jVs3\n" +
                "dWRkWca5Mmm3VQZlmxcNeFyTAgSth0GNalwWSVNcPK9W/VaDX8ecw7xYU04cpbQr\n" +
                "a4JF9oc33bhgn4ZDdcvcP8/QUQP+TyN4vGjp1k9+AgkIsJjLanqHE29chsh7ZcVF\n" +
                "GDjq3DppEo/Hh647rYRqXpxLfJB6fsDyYLmqNKsBcgtBqE9DtiXQ16GuGFrePxd2\n" +
                "nRKcSWQbisEa1LHr8G4d0kwBMjIoPiEhw4sgEt1ZCiQPO1HXqaK7VN3PhPOqjyjf\n" +
                "Rt6lN5kVA3+Dd2DRov9NQ83TQPJdg7KD5cXqlEliiMR4G0gWh8QZ4oAp540A\n" +
                "=ucHU\n" +
                "-----END PGP MESSAGE-----\n";

        ByteArrayInputStream in = new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .decryptWith(getDecryptionKey())
                .doNotVerify()
                .build();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        assertThrows(IOException.class, decryptionStream::close);
    }

    private PGPSecretKeyRingCollection getDecryptionKey() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(keyAscii);
        return new PGPSecretKeyRingCollection(Collections.singletonList(secretKeys));
    }
}
