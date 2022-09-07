// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

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
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.exception.MessageNotIntegrityProtectedException;
import org.pgpainless.exception.ModificationDetectionException;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.TestAllImplementations;
import org.pgpainless.s2k.Passphrase;

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

    private static final String MESSAGE_TAMPERED_CIPHERTEXT = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcDMA3wvqk35PDeyAQv+NgaEl1h8ZLRD0YiGFqVyO4G0slWQotmgPuovBU8YpNPd\n" +
            "A/sROQAOpkxR0mSzhUpMcgkpwi1r7dC3HGQCf+mitGwe+JFXCTx7N/4t1U321BKj\n" +
            "c7k7Zu9pDHpPzWi52T6yL30dyR7XkU85P2BrZoOc7B6GuZF07f4qIG1c3+YzBWuw\n" +
            "cXyqAmLx/zHUkX72Ga6vzUX/ud08gGYeWthLim7jLG9JzNr+BGnOb93+bKTwe7GX\n" +
            "dxNkBP7NTtGaFBM9epvsBiMSBIUHxuJDFgN4KSzpTP3+tcgrpTAaNWalJPzzphqD\n" +
            "Iu7ZrBDARQb/8FIymHt0QITZXu3ml8WopiIDbC42JOt16aMy5VDbcP/LlVZn/DB7\n" +
            "xr3waDZoxIMhNDcnu8R0w25pbf9T6Lt90a8/UIewCVjciUF82TK6KWLJkTJhmRK3\n" +
            "QJ/XgkMhDhS94Rj+l+FIRxJF/oyTtRFoeBHOB8V5neqXmOgGf3aX5UIJu3pf+GH/\n" +
            "n+PEoyEw7S7gQxF4VV4S0kwBZlc6xwHfvO+NPf7W0rAtUxMdOl3LBLiILDxF+cq2\n" +
            "eKG76gkewCp4EhTfK+iDr4KlObXDzADm1cXRlqFhtoQZrHV0poZVw2kIwSlF\n" +
            "=3G7i\n" +
            "-----END PGP MESSAGE-----\n";

    private static final String MESSAGE_MISSING_MDC = "-----BEGIN PGP MESSAGE-----\n" +
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

    private static final String MESSAGE_TAMPERED_MDC = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcDMA3wvqk35PDeyAQv+NgaEl1h8ZLRD0YiGFqVyO4G0slWQotmgPuovBU8YpNPd\n" +
            "A/sROQAOpkxR0mSzhUpMcgkpwi1r7dC3HGQCf+mitGwe+JFXCTx7N/4t1U321BKj\n" +
            "c7k7Zu9pDHpPzWi52T6yL30dyR7XkU85P2BrZoOc7B6GuZF07f4qIG1c3+YzBWuw\n" +
            "cXyqAmLx/zHUkX72Ga6vzUX/ud08gGYeWthLim7jLG9JzNr+BGnOb93+bKTwe7GX\n" +
            "dxNkBP7NTtGaFBM9epvsBiMSBIUHxuJDFgN4KSzpTP3+tcgrpTAaNWalJPzzphqD\n" +
            "Iu7ZrBDARQb/8FIymHt0QITZXu3ml8WopiIDbC42JOt16aMy5VDbcP/LlVZn/DB7\n" +
            "xr3waDZoxIMhNDcnu8R0w25pbf9T6Lt90a8/UIewCVjciUF82TK6KWLJkTJhmRK3\n" +
            "QJ/XgkMhDhS94Rj+l+FIRxJF/oyTtRFoeBHOB8V5neqXmOgGf3aX5UIJu3pf+GH/\n" +
            "n+PEoyEw7S7gQxF4VV4S0kwBZlc6xwHfvO+NPf7W0rAtUxMdOl3LBLiILDxF+cq2\n" +
            "eKG76gkewCp4EhTfK+iDr4KlObXDzB/m1cXRlqFhtoQZrHV0poZVw2kIwSkA\n" +
            "=Ishh\n" +
            "-----END PGP MESSAGE-----\n";

    private static final String MESSAGE_TRUNCATED_MDC = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcDMA3wvqk35PDeyAQv+NgaEl1h8ZLRD0YiGFqVyO4G0slWQotmgPuovBU8YpNPd\n" +
            "A/sROQAOpkxR0mSzhUpMcgkpwi1r7dC3HGQCf+mitGwe+JFXCTx7N/4t1U321BKj\n" +
            "c7k7Zu9pDHpPzWi52T6yL30dyR7XkU85P2BrZoOc7B6GuZF07f4qIG1c3+YzBWuw\n" +
            "cXyqAmLx/zHUkX72Ga6vzUX/ud08gGYeWthLim7jLG9JzNr+BGnOb93+bKTwe7GX\n" +
            "dxNkBP7NTtGaFBM9epvsBiMSBIUHxuJDFgN4KSzpTP3+tcgrpTAaNWalJPzzphqD\n" +
            "Iu7ZrBDARQb/8FIymHt0QITZXu3ml8WopiIDbC42JOt16aMy5VDbcP/LlVZn/DB7\n" +
            "xr3waDZoxIMhNDcnu8R0w25pbf9T6Lt90a8/UIewCVjciUF82TK6KWLJkTJhmRK3\n" +
            "QJ/XgkMhDhS94Rj+l+FIRxJF/oyTtRFoeBHOB8V5neqXmOgGf3aX5UIJu3pf+GH/\n" +
            "n+PEoyEw7S7gQxF4VV4S0ksBZlc6xwHfvO+NPf7W0rAtUxMdOl3LBLiILDxF+cq2\n" +
            "eKG76gkewCp4EhTfK+iDr4KlObXDzB/m1cXRlqFhtoQZrHV0poZVw2kIwSk=\n" +
            "=FDIu\n" +
            "-----END PGP MESSAGE-----\n";

    private static final String MESSAGE_MDC_WITH_BAD_CTB = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcDMA3wvqk35PDeyAQv+NgaEl1h8ZLRD0YiGFqVyO4G0slWQotmgPuovBU8YpNPd\n" +
            "A/sROQAOpkxR0mSzhUpMcgkpwi1r7dC3HGQCf+mitGwe+JFXCTx7N/4t1U321BKj\n" +
            "c7k7Zu9pDHpPzWi52T6yL30dyR7XkU85P2BrZoOc7B6GuZF07f4qIG1c3+YzBWuw\n" +
            "cXyqAmLx/zHUkX72Ga6vzUX/ud08gGYeWthLim7jLG9JzNr+BGnOb93+bKTwe7GX\n" +
            "dxNkBP7NTtGaFBM9epvsBiMSBIUHxuJDFgN4KSzpTP3+tcgrpTAaNWalJPzzphqD\n" +
            "Iu7ZrBDARQb/8FIymHt0QITZXu3ml8WopiIDbC42JOt16aMy5VDbcP/LlVZn/DB7\n" +
            "xr3waDZoxIMhNDcnu8R0w25pbf9T6Lt90a8/UIewCVjciUF82TK6KWLJkTJhmRK3\n" +
            "QJ/XgkMhDhS94Rj+l+FIRxJF/oyTtRFoeBHOB8V5neqXmOgGf3aX5UIJu3pf+GH/\n" +
            "n+PEoyEw7S7gQxF4VV4S0kwBZlc6xwHfvO+NPf7W0rAtUxMdOl3LBLiILDxF+cq2\n" +
            "eKG76gkewCp4EhTfK+iDr4KlObXDzB/n1cXRlqFhtoQZrHV0poZVw2kIwSlF\n" +
            "=nOqY\n" +
            "-----END PGP MESSAGE-----\n";

    private static final String MESSAGE_MDC_WITH_BAD_LENGTH = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcDMA3wvqk35PDeyAQv+NgaEl1h8ZLRD0YiGFqVyO4G0slWQotmgPuovBU8YpNPd\n" +
            "A/sROQAOpkxR0mSzhUpMcgkpwi1r7dC3HGQCf+mitGwe+JFXCTx7N/4t1U321BKj\n" +
            "c7k7Zu9pDHpPzWi52T6yL30dyR7XkU85P2BrZoOc7B6GuZF07f4qIG1c3+YzBWuw\n" +
            "cXyqAmLx/zHUkX72Ga6vzUX/ud08gGYeWthLim7jLG9JzNr+BGnOb93+bKTwe7GX\n" +
            "dxNkBP7NTtGaFBM9epvsBiMSBIUHxuJDFgN4KSzpTP3+tcgrpTAaNWalJPzzphqD\n" +
            "Iu7ZrBDARQb/8FIymHt0QITZXu3ml8WopiIDbC42JOt16aMy5VDbcP/LlVZn/DB7\n" +
            "xr3waDZoxIMhNDcnu8R0w25pbf9T6Lt90a8/UIewCVjciUF82TK6KWLJkTJhmRK3\n" +
            "QJ/XgkMhDhS94Rj+l+FIRxJF/oyTtRFoeBHOB8V5neqXmOgGf3aX5UIJu3pf+GH/\n" +
            "n+PEoyEw7S7gQxF4VV4S0kwBZlc6xwHfvO+NPf7W0rAtUxMdOl3LBLiILDxF+cq2\n" +
            "eKG76gkewCp4EhTfK+iDr4KlObXDzB/m1MXRlqFhtoQZrHV0poZVw2kIwSlF\n" +
            "=Ak00\n" +
            "-----END PGP MESSAGE-----\n";

    /**
     * Messages containing a missing MDC shall fail to decrypt.
     * @throws IOException in case of an io-error
     * @throws PGPException in case of a pgp error
     */
    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testMissingMDCThrowsByDefault() throws IOException, PGPException {

        PGPSecretKeyRingCollection secretKeyRings = getDecryptionKey();

        InputStream in = new ByteArrayInputStream(MESSAGE_MISSING_MDC.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKeys(secretKeyRings, SecretKeyRingProtector.unprotectedKeys())
                );

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        assertThrows(EOFException.class, () -> {
            Streams.pipeAll(decryptionStream, outputStream);
            decryptionStream.close();
        });
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testTamperedCiphertextThrows() throws IOException, PGPException {
        ByteArrayInputStream in = new ByteArrayInputStream(MESSAGE_TAMPERED_CIPHERTEXT.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKeys(getDecryptionKey(), SecretKeyRingProtector.unprotectedKeys())
                );

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        assertThrows(ModificationDetectionException.class, decryptionStream::close);
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testIgnoreTamperedCiphertext() throws IOException, PGPException {
        ByteArrayInputStream in = new ByteArrayInputStream(MESSAGE_TAMPERED_CIPHERTEXT.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKeys(getDecryptionKey(), SecretKeyRingProtector.unprotectedKeys())
                        .setIgnoreMDCErrors(true)
                );

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testTamperedMDCThrowsByDefault() throws IOException, PGPException {
        ByteArrayInputStream in = new ByteArrayInputStream(MESSAGE_TAMPERED_MDC.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKeys(getDecryptionKey(), SecretKeyRingProtector.unprotectedKeys())
                );

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        assertThrows(ModificationDetectionException.class, decryptionStream::close);
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testIgnoreTamperedMDC() throws IOException, PGPException {
        ByteArrayInputStream in = new ByteArrayInputStream(MESSAGE_TAMPERED_MDC.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKeys(getDecryptionKey(), SecretKeyRingProtector.unprotectedKeys())
                        .setIgnoreMDCErrors(true)
                );

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testTruncatedMDCThrows() throws IOException, PGPException {
        ByteArrayInputStream in = new ByteArrayInputStream(MESSAGE_TRUNCATED_MDC.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKeys(getDecryptionKey(), SecretKeyRingProtector.unprotectedKeys())
                );

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        assertThrows(EOFException.class, () -> Streams.pipeAll(decryptionStream, out));
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testMDCWithBadCTBThrows() throws IOException, PGPException {
        ByteArrayInputStream in = new ByteArrayInputStream(MESSAGE_MDC_WITH_BAD_CTB.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKeys(getDecryptionKey(), SecretKeyRingProtector.unprotectedKeys())
                );

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        assertThrows(ModificationDetectionException.class, decryptionStream::close);
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testIgnoreMDCWithBadCTB() throws IOException, PGPException {
        ByteArrayInputStream in = new ByteArrayInputStream(MESSAGE_MDC_WITH_BAD_CTB.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKeys(getDecryptionKey(), SecretKeyRingProtector.unprotectedKeys())
                        .setIgnoreMDCErrors(true)
                );

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testMDCWithBadLengthThrows() throws IOException, PGPException {
        ByteArrayInputStream in = new ByteArrayInputStream(MESSAGE_MDC_WITH_BAD_LENGTH.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKeys(getDecryptionKey(), SecretKeyRingProtector.unprotectedKeys())
                );

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        assertThrows(ModificationDetectionException.class, decryptionStream::close);
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testIgnoreMDCWithBadLength() throws IOException, PGPException {
        ByteArrayInputStream in = new ByteArrayInputStream(MESSAGE_MDC_WITH_BAD_LENGTH.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(in)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKeys(getDecryptionKey(), SecretKeyRingProtector.unprotectedKeys())
                        .setIgnoreMDCErrors(true)
                );

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void decryptMessageWithSEDPacket() throws IOException {
        Passphrase passphrase = Passphrase.fromPassword("flowcrypt compatibility tests");
        String key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n" +
                "Version: FlowCrypt 6.9.1 Gmail Encryption\r\n" +
                "Comment: Seamlessly send and receive encrypted email\r\n" +
                "\r\n" +
                "xcaGBFn7qV4BEACgKfufG6yseRP9jKXZ1zrM5sQtkGWiKLks1799m0KwIYuA\r\n" +
                "QyYvw6cIWbM2dcuBNOzYHsLqluqoXaCDbUpK8wI/xnH/9ZHDyomk0ASdyI0K\r\n" +
                "Ogn2DrXFySuRlglPmnMQF7vhpnXeflqp9bxQ9m4yiHMS+FQazMvf/zcrAKKg\r\n" +
                "hPxcYXC1BJfSub5tj1rY24ARpK91fWOQO6gAFUvpeSiNiKb7C4lmWuLg64UL\r\n" +
                "jLTLXO9P/2Vs2BBHOACs6u0pmDnFtDnFleGLC5jrL6VvQDp3ekEvcqcfC5MV\r\n" +
                "R0N6uVTesRc5hlBtwhbGg4HuI5cFLL+jkRwWcVSluJS9MMtug2eU7FAWIzOC\r\n" +
                "xWa+Lfb8cHpEg6cidGSxSe49vgKKrysv5PdVfOuXhL63i4TEnKFspOYB8qXy\r\n" +
                "5n3FkYF/5CpYN/HQaoCCxDIXLGp33u03OItadAtQU+qACaGmRhQA9qwe4i+k\r\n" +
                "LWL3oxoSwQ/aewb3fVo+K7ygGNltk6poHPcL0dU6VHYe8h2MCEO/1LR7yVsK\r\n" +
                "W47B4fgd3huXh868AX3YQn4Pd6mqft4WdcCuRpGJgvJNHq18JvIysDpgsLSq\r\n" +
                "QF44Z0GOH2vQrnOhJxIWNUKN+QnMy8RN6SZ1UFo4P+vf1z97YI2MfrMLfHB/\r\n" +
                "TUnsxS6fGrKhNVxN7ETH69p2rI6F836EZhebLQARAQAB/gkDCDyuMzkoMQjC\r\n" +
                "YLUdlPhViioPQAb/WMfaiE5ntf3u2Scm1mGuXTQsTmU2yTbY3igXTJ6YJH4C\r\n" +
                "FLB18f6u+NhZb0r97LteF4JiuTtm6ZA63ejSgp/5Lns1Z5wY7pMNPsH0cTU3\r\n" +
                "UrFQh/ghoxanSHaN1XQpaovYsOHfsWcYzAxtvqhDV2vqfIlhiL6EdE7Vn84C\r\n" +
                "QE096Gu4iMtKZSXCDU9B1XN2+rK2e+9c1nQHAXjAq49v9WUzstzjvrCmBajU\r\n" +
                "GS6Ccy3VHRel458boMNOZqvLOBCtw4nx2GFDs16ZQNZFywj1pThExKMxHlnB\r\n" +
                "Sw6tMJ0FJBCk2E9S28Buudu6sJJerZGjUKIafoSCcO8wpvixzL1s4dqJs+iH\r\n" +
                "Rv04xfHk78rgaP010NwoqHjd+ops+NxLoC9dS5PcDm9CAuBxRjf9gSJ8Qo8w\r\n" +
                "1jeldj93qiYU4Z0O87rzW+IDX6GBIcE8JghpOO+XMxN0nfb2EZpkFhBLe62j\r\n" +
                "JOgQsdoYy+iBKGSgx2uoHIvifxiq827XGCXTZmHkAwZyJPl7myja/qdiudlD\r\n" +
                "FnBtOexTnZ77HXlFC9s7/PItZZqKnIPuIKhsW/Tk8fzpUPf7Uu0tS/vCzc8+\r\n" +
                "abrpQM2ppI7O93kCKJdXVzKioE2MfV5DhLjNOe82ORWZO4uwCg2u8ZHhCOzz\r\n" +
                "MsMpAm89f+1nvOQtvBS9v45MhZdbndwPHQEg2pM689ZxHw9EgPiOhyOMFGM1\r\n" +
                "4tBZ3jYfPxGxTW7NZfryWUQxvSSkFaLsPMjxTB93T/fsJdeUDGKJR44cRweP\r\n" +
                "ATQWK/EBgx1d+jJUHKYl5aHUxdKLvwH1ikzgHuKkb4pV0yaRjONy8sEgXYkj\r\n" +
                "HoH1qfZAqbCoqraRorTEgO9QvzaLKb9gdDjEMxuzEJuA3QxP9HqHR5aU+T8o\r\n" +
                "hXss9SMFVjVok6t92v6keeUVRJYxjhoROZNUeMwfIg/EQEXACQUIGokJqaYC\r\n" +
                "4TX3GoLWa5+BTw5ChKiRC9VOyFNvq8Q2euBzSRoYPYUU7ekDawUQU+SCpN0I\r\n" +
                "3HYiJlGzDJ7zwFybeEMdv1F94F4NefROdRFcPtzrAJ4LM38zoq2YEUyK9RN0\r\n" +
                "lO2I9BFw30AR+Ps/qxtptWtzNXBohYuNNpaZt2UMcMOZhRYmHJjq59oH65X9\r\n" +
                "/l8wEk4nxgFmCjnpHyGpn2jtdMtRDrwAeHKBJ4ZQUV3SU/cgpc0VZ2rg+ZqL\r\n" +
                "7iAWfofoD/M/3bEOu6ePqcl2bKOhw8RT07CimovKUcXujp7/hsj47yNGKASs\r\n" +
                "rZMyJXT+VqMA/MWb++jOUwQkCz6dlzM8W5UC2ezlm1uIX+nrZp0LoWzq2VGG\r\n" +
                "ENbDpnyXh0W3FmVeSgwej1Fg7AJ4wdLkPxeb916UGONrUbFYRtE7jAo/h9c3\r\n" +
                "kus/8rsxMVfTvQu+tZPO7liWxhuuRWaG+YOJe2s8NYuqlyyPpvKRtGIqy363\r\n" +
                "c9j5VnfqOil1SxAjEgm7E5AHkCdQD2/BL4+hReex27WejedSHRVyQ6M8H0RO\r\n" +
                "+48eflFeaCTTWE970HIZ1hMQTf3bLEaB08758UuYVa7geF6jQmpg8OnkRPBQ\r\n" +
                "acQHgBOV1Fzf0an0uMhVw0vBQIX3XdaLe+uVUuvl00VOLB4JErCQzKDGsAMj\r\n" +
                "N2uE1cACfAEauTMik9+/G5wp2hW8JOO1mrH7lq7z3RzhJN/VkTFFSOGy/mB1\r\n" +
                "yu4inb+u5aVyJIL5ljs/NBno9b/aDOUmmiHw4my0KCQVdGNbletqfjeJV4gM\r\n" +
                "IQnXYXlQgg398LBawCNLYHkb/dDNO0Zsb3dDcnlwdCBDb21wYXRpYmlsaXR5\r\n" +
                "IDxmbG93Y3J5cHQuY29tcGF0aWJpbGl0eUBnbWFpbC5jb20+wsF/BBABCAAp\r\n" +
                "BQJZ+6ljBgsJBwgDAgkQrawnnJUJMgcEFQgKAgMWAgECGQECGwMCHgEACgkQ\r\n" +
                "rawnnJUJMgfO5g//audO5E7KXiXIQzqsVfh0RpOS5KwDa8ZNAOzbBjQbfjyv\r\n" +
                "jnvej9pYy+7Pot9NDfGtMEMpWj5uWuPhD1fv2Kv/uBP4csJqf8Vbs1H1hD4s\r\n" +
                "D21RrHerM7xCFzIN1XHhkemR7IALNfekrC9TGi4IYYZrZKz/yK0lCjT8BIro\r\n" +
                "jYUE5CODa8mKPB2BSmJwqNwZxhr0KKnPykrOAZfpArnHEdY3JE54Se6FCxKM\r\n" +
                "WOtnKBHcwHiSTsX/nBtK30sCul9j1Wgd1jFRJ244ESJd7M6cBlNrJ6GTZDil\r\n" +
                "rmpo9nVO0slTwD/YD6GCyN3r3hJ3IEDnwZK05pL+1trM6718pyWaywfT62vW\r\n" +
                "zL7pNqk7tIghX+HrvrHVNYs/G3LnN9m5zlCJMk5wKP+f9olsz3Llupam2auk\r\n" +
                "g/h1HXEl3lli9u9QkJkbGaEDWR9UCnH/xoybpS0mgjVYt0B6jNYvHBLLhuaj\r\n" +
                "hR+1sjVIIg0kwfxZfQgFXyAL8LWu4nNaSEICUl8hVBWf9V6Xn4VX7JkkWlE3\r\n" +
                "JEByYiuZkADhSdyklJYkR9fQjUc5AcZsUgOuTXsY4fG0IEryMzrxRw0qgqG1\r\n" +
                "7rir1uqrvLDrDM18FPWkW2JwGzF0YR5yezvvz3H3rXog+ryEzeZAN48Zwrzv\r\n" +
                "GRcvEZJFmB1CwTHrW4UykC592pqHR5K4nV7BUTzHxoYEWfupXgEQAK/GGjyh\r\n" +
                "3CHg0yGZL5q4LJfn2xABV00RXiwxNyPc/7YzYgSanBQmzFj3AMJhcFdJx/Eg\r\n" +
                "3i0pTr6qbAnwzkYoSm9R9k40PTA9LP4AMBP4uXiwbbkV2Nlo/RMgmHN4Kquz\r\n" +
                "wY/hbNK6ZujFtDGXp2s/wqtfrfmdDnXuUhnilrOo6NR/DrtMaEmsXTCfQiZj\r\n" +
                "nmSkAEJvVUJKihb9C51LzFSWPYEMkjOWo03ZSYJR6NjubjMK2hVEbh8wQ7Wv\r\n" +
                "vdfssOiwO+gwXw7zibZphCMA7ADVqUeM10q+j+TLGh/gvpm0ghqjKZsdk2eh\r\n" +
                "ncUlTQhDkwY8JJ5iJ6QThgjYwaAcC0Ake5rA/7nPn6YMnxlP/R7Nq651l8SB\r\n" +
                "ozcTzjseOSwearH5tMeKyastTWEIHFAd5rYIEqawpx9F87kLxRhQj9NUQ6uk\r\n" +
                "mdR66P8elsm9AZdQuaQF53oEQ5zwuUK8+wXqDTC853XtfHsCvxKENP0ZXXvy\r\n" +
                "qVo2INRNBO5WlSYQjGxoxohs1X+CMAmFSDvbV70dZVf0cQJ9GidocAv70DOH\r\n" +
                "eXBuOiXZBqyGSNjecPl2bFr4A6r5RMnNZDrYieXJOEWUqgaX0uNQacX4Aecm\r\n" +
                "KiCEyR08XKEPVnnJGUM7mOvhuGdH0ZC03ZUPqLAhfW2cxcsiOeTQ7tc8LLaT\r\n" +
                "u348PxVsPkN19RbBABEBAAH+CQMIXnc7lrdca0Rg8eLOHqbZ4HZeKswdL0Jg\r\n" +
                "lNZ9Fnp2ZPOgrnYxqeCbpRoZwr09aZ/DYiUfUgDuuJIRFzmorhczyKMOWTW+\r\n" +
                "eTTGFWIJB4ANAGie4EUhrJe4cDFxPg4Uvuvk/KMt5kLTOcSaN70kIKvt2lQT\r\n" +
                "LFzi6gCW9TWAtf5Jg+CcOoOw0tIsBcxTSL2V6SQDAS9KBJcgyhQAvbey44Zb\r\n" +
                "8s8kmtt1Xwl9bEtG2uDvKNvbb1GszeXf1wW2acwO4OAmrJXMhOscWb6eiDx+\r\n" +
                "9sIM5VoDrUG6K+72VSn9xqbEE9K5+U83qeAIb8dn+FLuKR0+auAJF19bkCUz\r\n" +
                "ZQS3wXzCm/D+PqE+BWexd7Jd8m/zg0eSzw+0hAxQ7sw5c2EdZ6LmqA1qs6yU\r\n" +
                "gIk92HufgO+fpRnUVRhD7ZklxfaG3dLIdbOs5R6DdA9z015r2VOh4S5mLJfY\r\n" +
                "rCQqEtqbtJpUOreyXejDYOCvv/mpFa81EWOMGmySvEPK7d25VAgIM/MS2l2H\r\n" +
                "+oJ7nMI4ZxgB7W4nVz15YK3RoJKAlcyy//1MAyNbH3TU8rytOKcPfCB7qgAP\r\n" +
                "6yjBGrej0IzuMWBmuuLCvfiYIqYDBgZ6GruAJhuudPXbhojl0l9z+lcM94IU\r\n" +
                "GOoGGhUIy3Zgt2nLQFB4vegY2EYUBMOO6dYeMh2QMwlSU63cnpxE/w6wby8b\r\n" +
                "RZ4GDPEBmYkCTZ0vbV34vJ72Z+LJ0/FOrTuQA8RHUJ7LMkTV5OF8oo20cE9O\r\n" +
                "h8Eyay+yYtccL2M8mpiJ9FXOyxURVyz4VaDfSXfo2auSzvUALVA/kMT3IVWZ\r\n" +
                "929TCb5uI/KwcqIMlP5Ih5hj0+0C34v5XnkNDLO8G3bcQ+NAb3ydUg5FpERy\r\n" +
                "0vW5TtgQmf04CdPJ341urINodtrUSabiOqBHSTLVaaYbSFcGF7Ur4lRwDlx3\r\n" +
                "50JqAcbp8Dl2eKMjW7EkHnTaKKC7lJwG62I3XbVg4mdkgzNAOF9UKjdHVn7Q\r\n" +
                "/DU3m67ZN5wwSruffu6DWNrDnytpl9Hdw2s9AF5UN1WfxobO7OD2vQPJ8Fcg\r\n" +
                "8kPUgnJ1OzBtvzNP53Aorbd8RDxx7rBQBtCFQN8Uq1ksUKiYNqbeRZ6vOtmH\r\n" +
                "LhiyhjMsrF0cog7r86dAAlWQJLnv+zUtdZ2LGS3aGMjAb7Y/iOVS5Q6/7Zw9\r\n" +
                "3wKAAfl7vFdZ7TFzq/p1/+xwc42WtO96XjFCtqKtpQ4sGRMUt7zUuq8ZJk26\r\n" +
                "ja94/v6iHhR9GID3HNiDLRvpQPFiK5PM5p6EI0Z5JfL5OQjvsmv/ltu5XmO6\r\n" +
                "08uXoZJM7IwPBdGZ7yNrDu0E9MEU7UW5kgSQzeGESV+jw2rXxU6wXeIAhkGh\r\n" +
                "um7f0JoKqYYOjRDLAXOtJgVAHGcto+U4XJQK4Bv7ohCpP0M+hSrEU1uYGC1G\r\n" +
                "4O6GSpN+4WV99i+JLFBya0R0ZUZfKQuU0EjRXX39WKT5LX7cUTTMHtuY3Xd/\r\n" +
                "BC/YMFqbk5+MZ0P1L1awJGkhMSc1qCrQ1OEtMk49ak2IrT+E19gQ6lR3q7yQ\r\n" +
                "B5D7ys/Z5X0ZbTsy6GK5JZE3X31of/DTbigqWLENk3oh5OaDNZ1hYUmHe03s\r\n" +
                "QuVrwD8TWqig4/KfQgFrUDLEdTZJezUsybHzjzWw5E8+5WrlBnx5PERaZzBF\r\n" +
                "wubVzAIAD9NsRGAzEF0ZBIsqzcxMQzF0jnvtl7YENQuH9ZYNuZY9h9f8uczV\r\n" +
                "6WM2HmQioFUswnzC+FNwC9Re+NNjrtdQAsVJAnn2BW4tvXlYb37foe0r8WDk\r\n" +
                "ULZ4Q8LBaQQYAQgAEwUCWfupZAkQrawnnJUJMgcCGwwACgkQrawnnJUJMge5\r\n" +
                "uA/+NA4zV+NWRNIpkyTDPD7FGi4pmFcMUs96Wzcedx244au4ixLLprSOib5e\r\n" +
                "A1UImjRWptJII6rZJCHVrB/rFJVQhSHaJQCsSd8K0N1DOOrv4oaGrL9zyzPd\r\n" +
                "ATW8izY9rzIRaNg9Si8DvULfKIheLI429RWDfeYFjFPVJ8n55gwaf28Nptxs\r\n" +
                "yo4mEWhf+pF/l8HaQtOzLB82PE4NXwrzf2MogNz3W5BMvcWZo1Vma4Iz1IJf\r\n" +
                "HdNlZYJO1vMC7u/7JYAztyH50mXT9Jh6U2jim5OElFRNEUh35E1L2G6XzRdO\r\n" +
                "JrEXbghF7EO+iekIyRScf2pE+vNBhL2iwnJs+ChgFDFIGnR+Zjwl3rG8mux0\r\n" +
                "iykse5vOToid8SEZ16nu7WF9b8hIxOrM7NBAIaWVD9oqsw8u+n30Mp0DB+pc\r\n" +
                "0Mnhy0xjMWdTmLcp+Ur5R2uZ6QCZ0lYzLFYs7ZW4X6mT3TwtGWa7eBNIRiyA\r\n" +
                "Bm5g3jhTi8swQXhv8MtG6eLix8H5/XDOZS91y6PlUdAjfDS34/IeMlS8SM1Q\r\n" +
                "IlBkLHqJ18viQNHqw9iYbf557NA6BVqo3A2OVPyyCVaKRoYH3LTcSEpxMciq\r\n" +
                "OHsqtYlSo7dRyJOEUQ6bWERIAH5vC95fBLgdqted+a5Kq/7hx8sfrYdL1lJy\r\n" +
                "tiL0VgGWS0GVL1cZMUwhvvu8bxI=\r\n" +
                "=2z30\r\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\r\n";
        // longId = "ADAC279C95093207"

        PGPSecretKeyRing secretKeyRing = PGPainless.readKeyRing().secretKeyRing(key);

        String ciphertext = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: FlowCrypt 5.5.9 Gmail Encryption flowcrypt.com\n" +
                "Comment: Seamlessly send, receive and search encrypted email\n" +
                "\n" +
                "wcFMA0taL/zmLZUBAQ/7Bwida5vvhXv5Zi+qJbG/QPst11jWfljDQlw1VLzF\n" +
                "ou8ofoIEHpvoFgXegZUnoQXBmlHGD+XLs9jG/TV1mtE2RWq4hDtqiTQ6rEIa\n" +
                "brN3Nx77Yr+4EN1aKI20aTLEPTIjVU2GH2i9DAmjHteBU3nkL9Z3yecB8Pn8\n" +
                "EdhpCRY6cj2yrhJ5MPwmXrus9OFv39wA2DqYpqW5Be+KD8mipZ2CtJo5xtin\n" +
                "aeEhpWSDsdg26rjx1nz4dA0NcFzZK2p/BPfPIFzRvmoXoWFigpUnwryEoCqX\n" +
                "/tgmcrv7PqiYT5oziPmMuBc1lb7icI/Aq69uXz2z6+4MJHOlcTEFygV36J+1\n" +
                "1opcjoX+JKJNn1nvHovBxuemcMwriJdmDj4Hmfo4zkd6ryUtGVrMVn8DbRp6\n" +
                "TWB/0MSE8cmfuiA5DgzdGbrevdL6RxnQDmalTHJ5oxurFQVoLwpmbgd36C4Q\n" +
                "xMfG1xEqFn5zvrCTGHg2OfS2cynal8CQDG0ZQCoWwdb0kT5D6bx7QKcuyy1/\n" +
                "1TXKnp1NamD5Uhu1+XuxD7EbvDYUWYh3bkqgslsoX+OUl+ONdtMD5PswArd5\n" +
                "KisD9UJuddJShL4clBUPoXeNrRxrU6HqjP5T4fapK684MeizicHIRpAww7fu\n" +
                "Z8YtaySZ/hoOAKWsx0rV4grgJV7pryj4ARBRa1pLL9rBwUwDS1ov/OYtlQEB\n" +
                "D/47fyD/6BvepqWmZXj7VLl2y63eE0b/6hf5K+Izv5A/+5l/EnjFx0rq+qeX\n" +
                "6hftYZBUAbbBvKfxq9D5xsWg3tnhFv2sYIE3YpkCSzZpWJmahHwQOVNT0ASw\n" +
                "gbO25OiTPlYPqfSkGYe0palbL+4T5dLOwVilmrZ2bQf/rLePwA4RQpWDPYio\n" +
                "NDU0Xfi7TQcHQrZTpwFbVzNPXgCHnQkqF+s0v8RDJHnt9vVs2KEpi49V/YgN\n" +
                "+gZnZOeADL0rbre/PrIck1YSjZLbrWtQVk4+sCf0TjvixJ7MNjA4NgdZPo0M\n" +
                "Hke/9XBFie3NiZaW/cEIVZ7WnjB3IbhkmOMJd4LgdHKgmswJwCYm+XvpOI19\n" +
                "FzU1vzZmfOA1nEJSuuCDNVUoKYIQA5UEYJrVJeGnVN5sU5jkdlX9xPtYceww\n" +
                "YFmLisuf9Ev0HC7v27KwYQRDPNYRA8GeK/jY6aZdg+VccsnzEigdYL5Tm4JI\n" +
                "Zrxp/G807bZvt0yZwWh0gpWOFgbVgrm4Hpji5ilDyulZSW+8nJxB5tDoPzL4\n" +
                "j4w9malje0c60GWNtiyCPLURyN63C2q144UpQjSU5r66oP1yF2A97aXKbf4p\n" +
                "qO7cSNWEOTpqJkJrNFVKQdWvXZ+mvW1PQFmkkwish2HiQIXmWb04uV1pI8hR\n" +
                "6YWk2ox9aZiJ664MpncgyJ5uIMlzVfYrX+AZRtBW36RgCTprIv6l1M5NcHMy\n" +
                "zEscTaSY/e+pM5HzQKSzX+zHLa5kk5L7veX+1G33saiqSJ/fK13+k7qDNZQD\n" +
                "nbtaebfh2JS0Pdbub6FUFjPHR5PydU9ltuppGEeYrOe1SxwiZ6BZfIXO2/8M\n" +
                "hA==\n" +
                "=B/NE\n" +
                "-----END PGP MESSAGE-----\n" +
                "\n";

        assertThrows(MessageNotIntegrityProtectedException.class, () -> PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(ciphertext.getBytes(StandardCharsets.UTF_8)))
                .withOptions(new ConsumerOptions().addDecryptionKey(secretKeyRing,
                        SecretKeyRingProtector.unlockAnyKeyWith(passphrase)))
        );
    }

    private PGPSecretKeyRingCollection getDecryptionKey() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(keyAscii);
        return new PGPSecretKeyRingCollection(Collections.singletonList(secretKeys));
    }
}
