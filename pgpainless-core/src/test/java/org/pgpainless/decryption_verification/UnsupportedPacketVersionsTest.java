// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;

public class UnsupportedPacketVersionsTest {

    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
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

    private static final String PKESK3_PKESK23_SEIP = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcDMA3wvqk35PDeyAQv/YP+fDWtifT7KSk+tWrgbyvsYCt5Wh0IPESTZuiptwvto\n" +
            "CGbOfwuPbqqzzlFqSvX3UiJwhxjSSB3a1EBIOsbhc4grip/wm+fB50S/nTJxkJ14\n" +
            "qid40D7HOcIvuz1iQr1QoMNB0oT3nCwMec8mPUX2yOzx1eqr62SZUTCr6FdAmdYI\n" +
            "1u4EAeEFhRO0rcPRrpMZqwkXtUfx+pu7OzBS0qmOlfkQ50kbETDXBik4iXi30AGl\n" +
            "Ifo792oRo6DFK7ENquTNRqFPfezjrGZfkJrPWulWh28GogWTpOBwfXG8X262QoIp\n" +
            "VwZygi7wfj1jh2sXPvWgHjsjjTt7HPAiLI1f6IUl8WCQfPuQkFwCwPv63/rve59v\n" +
            "sBaeCEykAxdzMbP1oYSBBtONSAPYW9fsUsJSpuuLvxH252+luk09uQXWd6z4aCDm\n" +
            "EXiolhbkzL3mXCpVP6nMjRkm2ERE1yAWgXGT9JON0gcCb3eVqw6wzOYu+Vwq70ND\n" +
            "vKYlTMY+9RUx7wLn51UgwUoXQUFBQUFBQUEJYWFhYWFhYWFhYWFhYWFhYWFhYWFh\n" +
            "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYdJMAQZo\n" +
            "tUFmYcTQrd5IFriHbF8h/Ov/xKlkW1QOPrZ+ziMQRbwyY4pVwNbZjCNVCHg5QDO4\n" +
            "wjF686DfZt83NvVYbJ7QNuENoI4YcFj8nw==\n" +
            "=VS1M\n" +
            "-----END PGP MESSAGE-----";

    private static final String PKESK23_PKESK3_SEIP = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wUoXQUFBQUFBQUEJYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh\n" +
            "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYcHAzAN8L6pN+Tw3sgEL/2D/nw1r\n" +
            "Yn0+ykpPrVq4G8r7GAreVodCDxEk2boqbcL7aAhmzn8Lj26qs85Rakr191IicIcY\n" +
            "0kgd2tRASDrG4XOIK4qf8JvnwedEv50ycZCdeKoneNA+xznCL7s9YkK9UKDDQdKE\n" +
            "95wsDHnPJj1F9sjs8dXqq+tkmVEwq+hXQJnWCNbuBAHhBYUTtK3D0a6TGasJF7VH\n" +
            "8fqbuzswUtKpjpX5EOdJGxEw1wYpOIl4t9ABpSH6O/dqEaOgxSuxDarkzUahT33s\n" +
            "46xmX5Caz1rpVodvBqIFk6TgcH1xvF9utkKCKVcGcoIu8H49Y4drFz71oB47I407\n" +
            "exzwIiyNX+iFJfFgkHz7kJBcAsD7+t/673ufb7AWnghMpAMXczGz9aGEgQbTjUgD\n" +
            "2FvX7FLCUqbri78R9udvpbpNPbkF1nes+Ggg5hF4qJYW5My95lwqVT+pzI0ZJthE\n" +
            "RNcgFoFxk/STjdIHAm93lasOsMzmLvlcKu9DQ7ymJUzGPvUVMe8C5+dVINJMAQZo\n" +
            "tUFmYcTQrd5IFriHbF8h/Ov/xKlkW1QOPrZ+ziMQRbwyY4pVwNbZjCNVCHg5QDO4\n" +
            "wjF686DfZt83NvVYbJ7QNuENoI4YcFj8nw==\n" +
            "=EhNy\n" +
            "-----END PGP MESSAGE-----\n";

    private static final String PKESK3_SKESK23_SEIP = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcDMA3wvqk35PDeyAQv/YP+fDWtifT7KSk+tWrgbyvsYCt5Wh0IPESTZuiptwvto\n" +
            "CGbOfwuPbqqzzlFqSvX3UiJwhxjSSB3a1EBIOsbhc4grip/wm+fB50S/nTJxkJ14\n" +
            "qid40D7HOcIvuz1iQr1QoMNB0oT3nCwMec8mPUX2yOzx1eqr62SZUTCr6FdAmdYI\n" +
            "1u4EAeEFhRO0rcPRrpMZqwkXtUfx+pu7OzBS0qmOlfkQ50kbETDXBik4iXi30AGl\n" +
            "Ifo792oRo6DFK7ENquTNRqFPfezjrGZfkJrPWulWh28GogWTpOBwfXG8X262QoIp\n" +
            "VwZygi7wfj1jh2sXPvWgHjsjjTt7HPAiLI1f6IUl8WCQfPuQkFwCwPv63/rve59v\n" +
            "sBaeCEykAxdzMbP1oYSBBtONSAPYW9fsUsJSpuuLvxH252+luk09uQXWd6z4aCDm\n" +
            "EXiolhbkzL3mXCpVP6nMjRkm2ERE1yAWgXGT9JON0gcCb3eVqw6wzOYu+Vwq70ND\n" +
            "vKYlTMY+9RUx7wLn51Ugw00XCQMINQp7MFzAc6T/YWFhYWFhYWFhYWFhYWFhYWFh\n" +
            "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYdJM\n" +
            "AQZotUFmYcTQrd5IFriHbF8h/Ov/xKlkW1QOPrZ+ziMQRbwyY4pVwNbZjCNVCHg5\n" +
            "QDO4wjF686DfZt83NvVYbJ7QNuENoI4YcFj8nw==\n" +
            "=pvWj\n" +
            "-----END PGP MESSAGE-----\n";

    private static final String SKESK23_PKESK3_SEIP = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "w00XCQMINQp7MFzAc6T/YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh\n" +
            "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYcHAzAN8L6pN+Tw3sgEL/2D/\n" +
            "nw1rYn0+ykpPrVq4G8r7GAreVodCDxEk2boqbcL7aAhmzn8Lj26qs85Rakr191Ii\n" +
            "cIcY0kgd2tRASDrG4XOIK4qf8JvnwedEv50ycZCdeKoneNA+xznCL7s9YkK9UKDD\n" +
            "QdKE95wsDHnPJj1F9sjs8dXqq+tkmVEwq+hXQJnWCNbuBAHhBYUTtK3D0a6TGasJ\n" +
            "F7VH8fqbuzswUtKpjpX5EOdJGxEw1wYpOIl4t9ABpSH6O/dqEaOgxSuxDarkzUah\n" +
            "T33s46xmX5Caz1rpVodvBqIFk6TgcH1xvF9utkKCKVcGcoIu8H49Y4drFz71oB47\n" +
            "I407exzwIiyNX+iFJfFgkHz7kJBcAsD7+t/673ufb7AWnghMpAMXczGz9aGEgQbT\n" +
            "jUgD2FvX7FLCUqbri78R9udvpbpNPbkF1nes+Ggg5hF4qJYW5My95lwqVT+pzI0Z\n" +
            "JthERNcgFoFxk/STjdIHAm93lasOsMzmLvlcKu9DQ7ymJUzGPvUVMe8C5+dVINJM\n" +
            "AQZotUFmYcTQrd5IFriHbF8h/Ov/xKlkW1QOPrZ+ziMQRbwyY4pVwNbZjCNVCHg5\n" +
            "QDO4wjF686DfZt83NvVYbJ7QNuENoI4YcFj8nw==\n" +
            "=STOd\n" +
            "-----END PGP MESSAGE-----\n";

    private static final String PKESK3_SKESK4wS2K23_SEIP = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcDMA3wvqk35PDeyAQv/YP+fDWtifT7KSk+tWrgbyvsYCt5Wh0IPESTZuiptwvto\n" +
            "CGbOfwuPbqqzzlFqSvX3UiJwhxjSSB3a1EBIOsbhc4grip/wm+fB50S/nTJxkJ14\n" +
            "qid40D7HOcIvuz1iQr1QoMNB0oT3nCwMec8mPUX2yOzx1eqr62SZUTCr6FdAmdYI\n" +
            "1u4EAeEFhRO0rcPRrpMZqwkXtUfx+pu7OzBS0qmOlfkQ50kbETDXBik4iXi30AGl\n" +
            "Ifo792oRo6DFK7ENquTNRqFPfezjrGZfkJrPWulWh28GogWTpOBwfXG8X262QoIp\n" +
            "VwZygi7wfj1jh2sXPvWgHjsjjTt7HPAiLI1f6IUl8WCQfPuQkFwCwPv63/rve59v\n" +
            "sBaeCEykAxdzMbP1oYSBBtONSAPYW9fsUsJSpuuLvxH252+luk09uQXWd6z4aCDm\n" +
            "EXiolhbkzL3mXCpVP6nMjRkm2ERE1yAWgXGT9JON0gcCb3eVqw6wzOYu+Vwq70ND\n" +
            "vKYlTMY+9RUx7wLn51Ugw1AECRcIYWFhYWFhYWFBQUFBYWFhYWFhYWFhYWFhYWFh\n" +
            "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh\n" +
            "YdJMAQZotUFmYcTQrd5IFriHbF8h/Ov/xKlkW1QOPrZ+ziMQRbwyY4pVwNbZjCNV\n" +
            "CHg5QDO4wjF686DfZt83NvVYbJ7QNuENoI4YcFj8nw==\n" +
            "=/uxY\n" +
            "-----END PGP MESSAGE-----\n";

    private static final String SKESK4wS2K23_PKESK3_SEIP = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "w1AECRcIYWFhYWFhYWFBQUFBYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh\n" +
            "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYcHAzAN8L6pN+Tw3sgEL\n" +
            "/2D/nw1rYn0+ykpPrVq4G8r7GAreVodCDxEk2boqbcL7aAhmzn8Lj26qs85Rakr1\n" +
            "91IicIcY0kgd2tRASDrG4XOIK4qf8JvnwedEv50ycZCdeKoneNA+xznCL7s9YkK9\n" +
            "UKDDQdKE95wsDHnPJj1F9sjs8dXqq+tkmVEwq+hXQJnWCNbuBAHhBYUTtK3D0a6T\n" +
            "GasJF7VH8fqbuzswUtKpjpX5EOdJGxEw1wYpOIl4t9ABpSH6O/dqEaOgxSuxDark\n" +
            "zUahT33s46xmX5Caz1rpVodvBqIFk6TgcH1xvF9utkKCKVcGcoIu8H49Y4drFz71\n" +
            "oB47I407exzwIiyNX+iFJfFgkHz7kJBcAsD7+t/673ufb7AWnghMpAMXczGz9aGE\n" +
            "gQbTjUgD2FvX7FLCUqbri78R9udvpbpNPbkF1nes+Ggg5hF4qJYW5My95lwqVT+p\n" +
            "zI0ZJthERNcgFoFxk/STjdIHAm93lasOsMzmLvlcKu9DQ7ymJUzGPvUVMe8C5+dV\n" +
            "INJMAQZotUFmYcTQrd5IFriHbF8h/Ov/xKlkW1QOPrZ+ziMQRbwyY4pVwNbZjCNV\n" +
            "CHg5QDO4wjF686DfZt83NvVYbJ7QNuENoI4YcFj8nw==\n" +
            "=cIwV\n" +
            "-----END PGP MESSAGE-----\n";

    private static final String PKESK3_SEIP_OPS3_LIT_SIG4 = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcDMA3wvqk35PDeyAQv+IhkCMhbdRcMnIPZNPGU6OK1Jk5xuRdIEIBsvv7b8jmAr\n" +
            "9IwjfnV/RDMtH+xR/T9K7qJGGFYnhLY5w0CmYHQcDKpcBqk0Dw6l/eKCNhgRXKAk\n" +
            "gfaKL1Utt1Pw0nz0mOwHyPEN/pGc0xlVhsjVkRvIOsKcpfuc1EpSZMFgDcBQDhe/\n" +
            "jAsR/MvRugkW8xLpyQyfeGLJUOEYVrkpam3rLKB1KywAgBmpr9WDwfYITW/VE9k5\n" +
            "cKIOPMDJFU+u9lzBx6nSS4JRBuCO2mhR4gjcRaGPWiiz+0qZfS+AXYV/MAU5OwK/\n" +
            "6nhX97zwS4r1Avztjh4taBhLVsY4pw6PuLtACJNwPrev63Yc+a4hJJ4pm1AnHV58\n" +
            "Y1pZKQL8vA61+/tbhFQ18vbJ8E1NOka/euFLQu9Mg58jhpcscqMouyr3JFMwgH2Y\n" +
            "eFuRJncJAKotXxlfnF37qz5LG3bamACXWZSObjp9d4quIAoCDUteZlDWQ1xq5R4y\n" +
            "QYXtk9ZuHsHsmY9A0CiI0sGYAUBtLubJ5qhLLr/GqKAmy8jTSA3MjgtrB55NWj9J\n" +
            "bjgFNsd1BNGklgnwhtmApHJWY8skAAQkJj0rXj/aOMc734ypiEWDiU1quRbEeRLR\n" +
            "kDvBNUXx2j2rVF+MmQS/sm5Yk/op+4lH/Wounsci3qWH76GaNZoIlvNE3mdFoVTe\n" +
            "cRh4W2Em8uAUH4bKwazltRJUhZmXvuGfUnQCmolJTpyPl4DaQQgzdBXLTRcPxwdU\n" +
            "30e7HnxZWESKx1LnGxp3Oan1k1lXyHwvnEk26EXhve+dhsQ6YsKgvtSLNFqGsfKe\n" +
            "MVOq37cpOGFQsYStWHZd0tcHjIjWmAeZ8kH+ZzR9tgYKxxjimsxafLS/lo415SkC\n" +
            "LnOCz6hywI7CufSUcXUlHGJuobZ5HDJcygsQhQmNVLDmKh4xUJDZrORS0ciMy2kc\n" +
            "XAnxCDYbltVQktc/F/Gl1lTx0UNmV5d9G0utVmxxGbXna3BLkB+6qMuux/ngC+cI\n" +
            "+0GjeuXDVzUqhKDDC3Sq4T2nwix4CjKvawnHC+vpHzRmdZSkXz3nrSdhJS5JnOap\n" +
            "I4CdyYkP3jQs5P03dkv5RZAoqNPkeftwadu0cjZj8HEC8bVSd7YCS/0Gbgvp/eK3\n" +
            "aOXZAWhELyQON4bbXiWzMTcO2AA5soBmP2QnBNdq7NxbEkBec8aAXZiyXn17JYit\n" +
            "HRtJ7beptXjN0y2bEhOvsBHbDpjGO22fZfQ0aywP2k4/XanDf4WJolEFgLj2Qp8F\n" +
            "pw1Olc2UhApxhAqjkme09hggli3wUhthQrpBlmntfbvBcmmO+p/jV8Zn\n" +
            "=Roko\n" +
            "-----END PGP MESSAGE-----\n";

    private static final String PKESK3_SEIP_OPS23_LIT_SIG23 = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcDMA3wvqk35PDeyAQv/byYGOehnfgZu/HJSSDEQhYE27lh5j+oQPktYBxsTI3Ii\n" +
            "AJ0pyJggtUM3c/e6z4HioAs4oQiaH1eoGBIl7noROhHJgT6E/oKdHJHmQndo0gT7\n" +
            "xzSHKrEZYEqT45LD6jT5teOiwGX/B7as6jaQOT+Nh+M0ZqpPrBdWDeUoY/I/lx9j\n" +
            "IcXQUhKuqJwZ16xsnv0JJ80rdp5qv0g2NHT1hK1JEONyT2fefov3EXaSpQZHRBEi\n" +
            "XfwToHcJrgemFoGwZBQhXsPWBgKH92aW6r7ZJZMQ4BE2SwqEw+cbaaqwfFRJ9puj\n" +
            "ZUBi2JGwnYImZyD7jYverkjH05vI7d5qQDhCT6GPD8Q0WKfY225LFTj/zzbC23lp\n" +
            "VLlbT2Ap8ZFOESpM+crOUaOguBhnTOF05s1eXhQYxIKzJTW8UVrzbwI8ut3BnEDj\n" +
            "0aDqUR+QDYgYmz8hnEjanHk2McvfaNdV6uOPZNph2RuPzhZeoNcz1PLy+XPFJsQT\n" +
            "EdqURJ2D35qmrBvq6klN0sGYAXEtW4hxMaKhH7/SIk2m3kUAChjtzr4XRcE2i8h3\n" +
            "9uD6CRWxokArfRVAp5RpXt3ywoYrl1Mp5prVwWcrTzYVPZwwe/bYAFTIfavi0Ezb\n" +
            "A/ah2e1EYCTWxLY0Klzil2Xw9/Dc/JPTRqzWJxIn0AU4DVfYNwlH3QimDUDKOKbu\n" +
            "bw4bLEEBKRr5BcNMA2rJOw/n3AmKxQcdSFJh3ZNtDPWzRwflIzE2qB686hpeOs34\n" +
            "T2iJcfr9W9rKcYI7+WYcZA3fWokaWUfXdWrPMXBVJuPdGezGLSfe/OM4kw/8s2vR\n" +
            "Bk88WZ1ZiFXE2CRaHP80fHFpxAZioWTuC5UGhF7NgZ7Q1E85GaGVe1fQeqmeX3mo\n" +
            "gwAWwq9WFhPQQPwdrDz+1h/pzD0RVW7D+zfWdF//vesc4z1Bpi5prbMdpVdmyvO9\n" +
            "8Rcc42GtmhtYSB9SPjzPuN8PrWvD3AKgw5vQro6oiNh0TGmj5Se4lXCfRfCl4tak\n" +
            "cmvdi+1wAvn5OFdxYKKHNvjavwj2SY70nx0ACasBpbMEwoQ0StZmOxCaofkgvEwN\n" +
            "t8jMq/MVrIfunhMjx0/GDpBZBb8kze8zrvWxlbTnoIfh2yVEqmTZWue9HX5Mnh8P\n" +
            "wexxNrPaafTjA3nUgXXzlItJ/Wa43pYw2sgcBPlF/jRKSFiD+pDLysqwpH0ANsJ3\n" +
            "G7t8Qavq1DlrHFgV5jhfR1tjA5ohjxx7yzceQBvZUFxKM1WEWR+9dRb3bpfZJr0g\n" +
            "qgO36bpCeCEej+ubXpXXTN28LQLXjQHlE2o1NGLoGl+G72tXOTx30kPS\n" +
            "=wUZn\n" +
            "-----END PGP MESSAGE-----\n";

    private static final String PKESK3_SEIP_OPS23_OPS3_LIT_SIG4_SIG23 = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcDMA3wvqk35PDeyAQwAmftqzbRiMRk7YbpJO7uqtWQIq2uZj7nYYOVpQgR777Zb\n" +
            "QT1J3pbPoCceWFSuHH/D0IeP84T95O+A630dtj3ZWhh4EGnBIKm13R6bEA4jKtcx\n" +
            "rK3HZyHo85N5TFn/gLOqCc2v/0cxUoygBqFpHFwBG/e4uuQoxgD4RsBGFrdYlyK7\n" +
            "MMkZ/fgaKhawTCVQ2dtBcp6WvKX/8u6FXSh35zFJJTM30LE7BFDgWEyGPLv0bWnl\n" +
            "37oCo8zcK+SIK4JooNm1ZxIowWTOxUz1pWPtmtGXA8XoGJtggXt+HpVxNE8bDCgV\n" +
            "f717+R0HMwQKP4F50Wq3Js9ZJrPjRvXLeiZe6nvqn5AQCOsG8osIIg2YElyW/uIe\n" +
            "C38OxaZbql297cYzzdEZtRYCTTY7j99pG8ZD1nNdd5IPm027dfPl+JJ5nzn/u3iT\n" +
            "+FKxgArZ9cYkeEpNB+BfWoWyNfbA830s3Y+G5wt3s4cmH1z8JvDeepUYhyqvA/6M\n" +
            "RInjwCUwSQCAuI+QhnPi0sOlAYOwkgN8RyqOP4vR4Kd1rJfm7rg2h40ag7tJtu5y\n" +
            "YXa4sU9DLpspTYvYgzRtsNbYHrH+LFkQlpG+PFnJAI6Qn+Q1zZsZ2HbbK7GOZFug\n" +
            "0wCg5E3DJQxBNlOx7h7xacpGb2QsmBTLUPvWFiYoq8He5XOx1MleLxO+E5l40kT4\n" +
            "ZE8RxfRyVreQdp3rZ6RMiIfnM8VljMxteaLmaIzqsLTlvKlf1w2DBRL9reI2oCP6\n" +
            "BukX8zba16ITsLELnuQ5L8EmQwcH8Yj8Mg37foyFHa2fIvZRg+0tz3b5nJKteWQn\n" +
            "u/qR/RGNAXT1D/YBQ+Tgnq6qIUd4Da/XEXAi8R6FKprc2yqCNzMSA1wolaq2DUGJ\n" +
            "ASyRN7uQJpVc1DlxTRTMQLpuoxljQtc6dmn/HKr7DF8jUKcM8cRk6PCqWd6PRYPq\n" +
            "WJTiHh2FoyDaR5+HuSbRCOr7i9jZXh/TctM70itLIvQlw/x9WEm2ZxwS7+0mHMvP\n" +
            "h9U4Wi70mfR0WllDNpWm5ZEeksoUF7aCQ2lVIQH8E6YGmWUSCYUgjgiIsfSqn9kh\n" +
            "tG8WGCrM1sPSIzQG70d1fuirRg5H7oeVRTPzpYN/cSXqRULk31Z9RneXwgZZZgPB\n" +
            "Q1hE3oJmP4LJEfRhL4P7TL2Xp+1Kvius53my2zKnVXoBNlAUHSdidXsd+xVaOEkE\n" +
            "cNyhLg4cZmlyuz5Ew/NHPAD70Cd9qXQraOf3dqZ77yhG0y/FCwXxnnfW1FnTLe14\n" +
            "3RWuNAFhbuNuYrXn0Zq+SFz3UnNNKMoNejwDcvkxxZ92KQXJcB7zCRnEehjBz/At\n" +
            "iNgsVfiOVRxzzp12iV+ljtM8A3KJHnnBQypPIeq4yKsXxtumVhryAc5k2neRZkvc\n" +
            "Wo1x3T/EY0SSlFFSYsiyDgbaj0SguiVNTrJbLQd62a1S4ZCYB5k2hlzm22eIKHIa\n" +
            "lb+sYaTGbSkxVH2xMvjxgO4dx9YvTlH6rsTIktmhvYxnF27Y6Bfhp+x8I3RoYPRC\n" +
            "ImMgllybYE9AOHLI5uogvoe133OfHAmHVm36qx+S24r8YTMdZ6iJKLCd0Hav6aS9\n" +
            "b4ptBiKQQQR2mtxaQNyBVEjfbpt2/ATnzRg5D/TAJATvhoeByWRYNP21iATnWU5c\n" +
            "H3uK3dNDLnZAbaEf2XfqEG2fcw/Bn9mbXUodEay+EQl0Z11kWKOBSwMyGwSxdMhw\n" +
            "S+9tTnfFZ73B/fyD41p3Ft02cUJcD2yW/j3+5JLOqZJJlTEhtAFvixkhcfR7VJTl\n" +
            "arZfECPXOOMbiBxQmFA4+AZfP+9bMFPz9/guZTkIWsjKO4JI6ge6ayl6Eel2Qsbo\n" +
            "MzsYA6m9h4a0VQPmHf1Itg5kiEpecG4rEqzJC2ov4mTiD4kVlPhUj6Je+VU3mEgT\n" +
            "geMf/8JkD6+IParbR7iaEQF2wPgrR/VcBX/5Y8AI4mW8eiTCybtPt9z4X6w326Uy\n" +
            "UkaqeswhQmd2sODDqxxrdjVmYQEWqVKIRRBLsR5fvDiqyiVFbPEO\n" +
            "=qFHk\n" +
            "-----END PGP MESSAGE-----\n";

    private static final String PKESK3_SEIP_OPS3_OPS23_LIT_SIG23_SIG4 = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "wcDMA3wvqk35PDeyAQv+JdNtgn26/Q4yXJ9egCmJ1/3SaeSB+y93jz+fmabMvc97\n" +
            "KbI1HN9RoG23UxDoQED+jGcbbrw+7ho73U3uRC4NtE4D4SZZMQZZXTadI0MEu4eN\n" +
            "yGgyFmZLy2Fek5N33m4PShvKqbeDnubmxv/lPlpz//KuxbVNPL+vtiVxZuI6vusB\n" +
            "q3T0Br0kH7OqCizCIKzl85d9hYAKXDaCaGw/0VXmFs0HgjBSB5RRHKt3GpVt83dI\n" +
            "b7vyyrzo6D0bwr+9nYC9Q+rku0lPNJutdSBRv9Xoc8eB7ud+0x9Ybj61C91gjvJp\n" +
            "NkeuqcCYOZw+iFckDR8+GUM4T5PO3dwxEVQUUeO99EKuCH2S/PqgrH8JFiRcCvED\n" +
            "SsngpAL3IfkoKCuAO0gpK4ebDKQ8R46ho/ER1UApT9A8lNbzLYIwCQ8fcK53AICe\n" +
            "XWDTGb1uqqkt0vFPxsKA0R6Wyk6gA8j8ta6zpgTpwGOyRbMKo8QW08mw+2UROCPj\n" +
            "/cdtV1Z6Iv0GrbKwrwB20sOlAYDKbSloZBhkwugYMqYWQfzPcM8S+sCX/+Kv/O79\n" +
            "oWucvbSAiUv0JlD6zqdNcileqJKCiiAVaCUZhLpZcgVWpLqfJuFFnHBOo98ARIHe\n" +
            "D5CzXn2sx+0ZlFW0fJk8Z2ZWXK9rKAleqsGB4dIA3WoC4UAFFjBqXG/4pa/H0He2\n" +
            "G8R3Q+wFqEaXYgm2Znq/+UxPGjAJLH7EUrwfBvK17eByT+bLqyZpKHhuZJXy/rw1\n" +
            "n+pCC1fedDWdxKj7+1Xw8cVlAWYCp2314DQjfI8BzFw0JWq8MU7hwGDQkJgfI3qH\n" +
            "RlBhIgE2iJAOQi4YaSgC9QaAxL4Uw3uo9+kwUGt87j+M4d7ALQ1XXLtCim6P36jP\n" +
            "kjOoAvfgwZ1NZEbzo/YS9/NK9KVXrhfgmkWSPjLaqJeur2Av9IkDuQmFF+EVxjRo\n" +
            "eQzZHk8RHOj03jjTZH/QHNiiUDfr2cMDj8Hi+r5pCvS/T67gymyE6VHQJSYS9dXP\n" +
            "0EMoe4jaG+aOdbAi3OPtKETSvtsKLflMR4k/RxRXN6lsV238wVna+w6nYZxqMqd4\n" +
            "fNnL5YUHZOEt2qxVguOCEZDANHoR0RFVXM6yBF36Ivwjhg5a1aujyHv150KwDDsc\n" +
            "YMI4O2pTcmhDX1aiV2X35EyLWJbSovbNj/IveMKa0q/xOXe4V8INX9Xv4sxm0mqY\n" +
            "RR8CY1E3cYG2g6Uhc4WkirSvXoN/IRq1MrYmcCHQrEDDBL5h/8/TIn/TAOZqBrZ/\n" +
            "gF1gfFW4ZgEcPZUeUmErHxLvdVqC+WK7/5qE86PXGo9yD9/Xxv5U7i8BbxgknUlD\n" +
            "SyRmBfzkRJudTHvH9wnk9KA5hPHqXk6ZkrBo4ugaiwUa/EejvkiHW7KRWijH57nL\n" +
            "JDzP13FU16gPuhPFTXP2zLvLeMSpVmkv2B9Mzvnrg+836B+hY0elAy5U/3D1/wxG\n" +
            "IjfDTsAcUQ8yULCRj6iZrx1SZc0HJDe4mjvqVqg0VOSpxGHfRNcte+zh6p8Fqqly\n" +
            "2O72vb49uEr54ZeL33j/ggCXWvMgdK7EtIirmzcwFsmamy89QSl1VzZzh5338n7f\n" +
            "9SOd67xL8BVSh8lee8ByuBiZryLbIuy1d8stndbbxLi+W7+Y/W08g3QyE+NwcpKd\n" +
            "/zTVViCZolgs4Ol73WEe6A131u+AMlJWXYD5tai+RmQOFugvCVX+QhezK1v3YrMH\n" +
            "KlIfFsh4Cq+JIo2jMMoVjLBK662kU24w8eaEagdIjBgd1XlEBgKUR/f754BOfoKi\n" +
            "JX2ySeHdQCCn/yc753X1TH3FNEThmJPHJG0ESkpIxqoTKdL3Ut+8BFlhWYwxCc8r\n" +
            "R8m9ixq0cQBXrNVaJsFVKqI9H4SJMc8ySGe8HYwJV2hhK9HbuhAfrKiJoUmoQHvD\n" +
            "jL9Y6H3ejK5YmqQ/zXoiepRfAklN3q+ByqhRMjZfDMuk0fcMaPy9RFoo1FqIPyqw\n" +
            "alekNaR/K4albyRcMoYxBhn3QFHf7VuaPuaxhg1ri3YfrWykv3RA\n" +
            "=jGpv\n" +
            "-----END PGP MESSAGE-----\n";

    private final PGPSecretKeyRing key;
    private final PGPPublicKeyRing cert;

    public UnsupportedPacketVersionsTest() throws IOException {
        key = PGPainless.readKeyRing().secretKeyRing(KEY);
        cert = PGPainless.extractCertificate(key);
    }

    @Test
    public void pkesk3_pkesk23_seip() throws PGPException, IOException {
        decryptAndCompare(PKESK3_PKESK23_SEIP, "Encrypted using SEIP + MDC.");
    }

    @Test
    public void pkesk23_pkesk_seip() throws PGPException, IOException {
        decryptAndCompare(PKESK23_PKESK3_SEIP, "Encrypted using SEIP + MDC.");
    }

    @Test
    public void pkesk3_skesk23_seip() throws PGPException, IOException {
        decryptAndCompare(PKESK3_SKESK23_SEIP, "Encrypted using SEIP + MDC.");
    }

    @Test
    public void skesk23_pkesk3_seip() throws PGPException, IOException {
        decryptAndCompare(SKESK23_PKESK3_SEIP, "Encrypted using SEIP + MDC.");
    }

    @Test
    @Disabled("Enable once https://github.com/bcgit/bc-java/pull/1268 is available")
    public void pkesk3_skesk4Ws2k23_seip() throws PGPException, IOException {
        decryptAndCompare(PKESK3_SKESK4wS2K23_SEIP, "Encrypted using SEIP + MDC.");
    }

    @Test
    @Disabled("Enable once https://github.com/bcgit/bc-java/pull/1268 is available")
    public void skesk4Ws2k23_pkesk3_seip() throws PGPException, IOException {
        decryptAndCompare(SKESK4wS2K23_PKESK3_SEIP, "Encrypted using SEIP + MDC.");
    }

    @Test
    public void pkesk3_seip_ops3_lit_sig4() throws PGPException, IOException {
        decryptAndCompare(PKESK3_SEIP_OPS3_LIT_SIG4, "Encrypted, signed message.");
    }

    @Test
    public void pkesk3_seip_ops23_lit_sig23() throws PGPException, IOException {
        decryptAndCompare(PKESK3_SEIP_OPS23_LIT_SIG23, "Encrypted, signed message.");
    }

    @Test
    public void pkesk3_seip_ops23_ops3_lit_sig4_sig23() throws PGPException, IOException {
        decryptAndCompare(PKESK3_SEIP_OPS23_OPS3_LIT_SIG4_SIG23, "Encrypted, signed message.");
    }

    @Test
    public void pkesk3_seip_ops3_ops23_lit_sig23_sig4() throws PGPException, IOException {
        decryptAndCompare(PKESK3_SEIP_OPS3_OPS23_LIT_SIG23_SIG4, "Encrypted, signed message.");
    }

    public void decryptAndCompare(String msg, String plain) throws IOException, PGPException {
        // noinspection CharsetObjectCanBeUsed
        ByteArrayInputStream inputStream = new ByteArrayInputStream(msg.getBytes(Charset.forName("UTF8")));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(inputStream)
                .withOptions(ConsumerOptions.get()
                        .addDecryptionKey(key)
                        .addVerificationCert(cert));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();

        assertEquals(plain, out.toString());
    }
}
