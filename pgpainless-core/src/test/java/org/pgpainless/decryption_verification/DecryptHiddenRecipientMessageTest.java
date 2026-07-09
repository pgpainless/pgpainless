// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.util.io.Streams;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.algorithm.OpenPGPKeyVersion;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.exception.MissingDecryptionMethodException;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.passphrase_provider.SecretKeyPassphraseProvider;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.TestAllImplementations;

public class DecryptHiddenRecipientMessageTest {

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testDecryptionWithWildcardRecipient() throws IOException, PGPException {
        String secretKeyAscii = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
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
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(secretKeyAscii);

        String message = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wcDMAwAAAAAAAAAAAQv6AvmrbeVN7u3VtFImNTpYVTN9lGF2i270Pt6xzHz4uCnh\n" +
                "LoIKHS67KX2oVBzcfyqEIXAsLO0yWEeSVVArbKV4e845x4DzV5W7iZ9hWuM1DuqR\n" +
                "pmfJ0SEFjc0BcUgSG5UWt/fmCYnN0vu17F2DnzVPBJ23xr70b5Pr3SooRt8cfaCs\n" +
                "RQcUHuE7qcoLLoFamww/HlNAhbgAQpUVgIJltLVwKQ6ksc5ZQ9Bu/OUoDLvzWBX4\n" +
                "a38ZeYP6PwPXfDgNf+6bMlCL0v69O/xwSu9kLfjti9v+q7PLKiuVvEWw8WM6KUYe\n" +
                "2zqKEdo6ITStoM2u9bfWOfYHj59pM+UPoZoWOtXNS96wjW/NK6oKwXoDFD+gj4SO\n" +
                "ofzy6bCbkmpcIE3jJlYKY9jVURCssCP5qTIZiIL2xGt/GMaYRzqNTdQkXYAqdLFT\n" +
                "zEaGXsNOiFtQtVXBhbo3p511yir8LblNbJiiJM24OgNV6Mq77qAsSZH4rwW9KJE/\n" +
                "uqrBxTR/5hyJAZOULu5J0kMBUsup74flyzMyczjng/dLz+jjppccQWcTfB1MujPI\n" +
                "rGNy478TPzwQwVJGDiS9zlOKhxHXb1tPI4wDjpTiohP5QFTG\n" +
                "=1knQ\n" +
                "-----END PGP MESSAGE-----\n";
        ByteArrayInputStream messageIn = new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8));
        ConsumerOptions options = ConsumerOptions.get()
                .addDecryptionKey(secretKeys);

        DecryptionStream decryptionStream = PGPainless.getInstance().processMessage()
                .onInputStream(messageIn)
                .withOptions(options);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();

        MessageMetadata metadata = decryptionStream.getMetadata();
        assertEquals(1, metadata.getRecipientKeyIds().size());
        assertEquals(0L, metadata.getRecipientKeyIds().get(0));

        KeyRingInfo info = new KeyRingInfo(secretKeys);
        List<OpenPGPCertificate.OpenPGPComponentKey> encryptionKeys =
                info.getEncryptionSubkeys(EncryptionPurpose.ANY);
        assertEquals(1, encryptionKeys.size());

        assertEquals(new SubkeyIdentifier(secretKeys, encryptionKeys.get(0).getKeyIdentifier()), metadata.getDecryptionKey());
        assertEquals("Hello Recipient :)", out.toString());
    }

    @Test
    public void testDecryptionWithWildcardRecipientAndMissingKeyFlag() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();
        String KEY_WITH_NO_ENC_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Comment: D1D3 6EAF BD15 3A37 063C  C1C7 E621 A2B6 0337 D4CF\n" +
                "\n" +
                "lQVYBGpPm+oBDAC8weB+1BNqbeiZRiOt37rp9ByjfmQJmhGACwA1rNzbBsXmPrzk\n" +
                "J+vaOozp45O4JyYMmsu7r9nynnerttf6G0GK1ul/1rJWffZlBgRSiukC7Ykzyit1\n" +
                "kpSxy881ng4ti4luV5o6a4hsSyiR6Qs0CH5mpZ02oflNff6vbrsYI11w8vhCSAfC\n" +
                "M7jntPjnd/1L70Dtsp5qdI7qwiMHuyejYjL8LKlpso8WwrH+S7wPJqV2Iwqrf+kf\n" +
                "6wT8fNDOSH1eLlITNUP7ny4KfSDwaxOXIFkaN+r7x4fR+7hkeQHLCkYq6M8mHNOW\n" +
                "1ezyQsFy6OkzNI63Gx1DTdfJEfEdjiw8aPJjeFc3ijYwn0pbpzJm3/3+iKBDw4pU\n" +
                "d2IMYBli4HHuGM8K2/2FhyouNL9SZz0V/ixTQxIng8u/sGFmw+N0bBT6/IHL+BqT\n" +
                "tzOQIKEWgLcFNGZXuMjQ4mT/7X3xxJ2Z3Rv3X5uTCPiJFc2KvQZk4brPKkQQBsFP\n" +
                "wA97ap8qi2SLvg8AEQEAAQAL/0FJ/ElSOL8E8kHl+VxgeSoIJknE43xQvsHfzDxE\n" +
                "pQXbg2M/Cx4N0u4id3BFJ+i4HdiZSGQMkOHzPyh1b6ISgGqyKITv8bKqEipiWOdm\n" +
                "Je+90snHoZ2izGztNqhwma3WSHySr4WKgV8X5hoGFjpyv6nomgb2IqHTtV7f+bYB\n" +
                "MYZqfEWM3aYmNsxqk/eYUNRNltNBB7uBwpdf/Dbl3PGN+12vYw/s08KHKILxlkRV\n" +
                "VUEWINAuR6gjJg/hamYXu8lyUpfGAyBFGL5YRqEBxy4ClnqRfN5uCvCjBmGVxSR5\n" +
                "Hqy40u2pXvOzu1dtNvwWGiRiBJN1TIwRPAtJ6u25Fp/sr8zR7DeKq6JCaXp2twyB\n" +
                "WDuqhARNdcBr5eWKsh+ovTDZ6gx+Lx/RpJ0qwKZy/DoQPfgfzxZ3+VlK7W6XL8o9\n" +
                "o3yp9TNQzjv7a8O4suYTnRjXOhRhrmaYuJ3o2V44UR6SvJPUREUARHtCkByxF5o2\n" +
                "Wc78PRL0Cjs6YSapfUVFTc3Z6QYAywO5a7C509uI0WsGvMKVpciKdTjmAnTzhQ8y\n" +
                "YtRMZoLja/GrEURU7k9AkTXGhVZULE6QPuncIt7Awv98t4bRGwOFeOCx74vB3Hp9\n" +
                "o91niwBPvDuhUurgWGMrvbouLsPsLxPu/u71fs8LRfXC+TfkWtoPn+vSydlRnWs3\n" +
                "qB0L0Pkf+/sx7n72nqVDELC1r+y3Wgx2mVwkjgRobaIv9ToANooBHXSraStHcD3N\n" +
                "CNTx2cLE1bs1oZQ4XWe96rMp4AC5BgDuBZEQXdazvLQv6a6RhDSn+NPNSwsw77X/\n" +
                "kaq/IENGxFMca/aK+G9UctGBjde81d3UtXTIj8bb3xA3o3pmvm9wBQFAApngNsbO\n" +
                "9Xzi2j1zDiu8+12apLuNnkii13CUlHlDMNKNnDoYw66JBdEgQNFTUT2uKjXT4kpL\n" +
                "4KX0ZQ+EzjiJ0UnH18evMPMIjn88Zb3HM/u1MxBHKRLoGY8t9V8/EOFZb6wFaoXA\n" +
                "I0Ka8q42Ztu2FCC2uA1s//7HNydDAQcGALHOC1OQ/HrNLNiyjaQZVoFCDHq4qsN+\n" +
                "6qgz/nM87aVRNuzMZDiU1WIhA61odbo7SmpN2Tb3qKcUDCpqAvp/95kQMcQgNZT9\n" +
                "rXeY7hSP07on1CLlw+TyF3bf9ICua7KoMr56SXXfdbWfhZYNsvC6fjX3nMfDoQAI\n" +
                "TDqtE3rKxhRr4XfXELzziOtNJdJ8SOVGx9Xf5DRoeHQ8kXu/eGA8QYFJtGlwyx2c\n" +
                "lxOUijjnxTm5mbG82gEV28dF84t7ZzSTpus/wsEaBB8BCgBOBYJqT5vsCRDmIaK2\n" +
                "AzfUzxahBNHTbq+9FTo3BjzBx+YhorYDN9TPApsBBRUKCQgLBRYCAwEABAsJCAcJ\n" +
                "JwkBCQIJAwgBAp4JBYkJZgGAAADdLQv/aDtLCIflAb2vmdKC/fIwuWdAAjrvKt+T\n" +
                "1rwXzRAhwO9GylrRiEf0wsjXuCBPpfecXLPtj1GFRMEp3PYHtgCLy5I3mzgSOZR1\n" +
                "ezHfX7siAGMgJ10Use2Ivz6IkmsIl2DzxNvTQDQDVxIglY1y5/DTIAhNSuQjg4FY\n" +
                "ZvINx8zMDRitewEBaO5gyk8kTQUVWl3Dj1p1g9bLHMGuP2uglk1h7Ig53eT0+tgt\n" +
                "NNke1z1KHT7N7DwiX8BMLm5en5a6zEMy8XqCM4j/P1jXEE0RlxzVOe4fbowm4CR5\n" +
                "sPnTOIBFWgAgNlDZ5UvRsx9979H1dmPfOEnFHlEtkEOgcKVJHORj1B88gSttSUtK\n" +
                "LFnOupS1U30I+y7PksTbZ+MOX1ijRZD1BWS3nK++rC0Znov2Uhr6MJxUf2u61OXf\n" +
                "fhTUlKumk6EDTaLjpsjgGJYoGx4naCwxxOGx4XhiaTe2p3qF/6vmuqRBosyULJxC\n" +
                "usrFAUnNW/kSkukyZiCYhMpN30ZQut4k\n" +
                "=7Gz+\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n";
        OpenPGPKey key = api.readKey().parseKey(KEY_WITH_NO_ENC_KEY);

        String ANONYMOUS_MESSAGE = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wcDMAwAAAAAAAAAAAQv/c6hHJVVJG+0fAA98wPkDnmpe1/RrgWFn7ja4lvINnaAX\n" +
                "DGmyfDvu5UUO6nFOD7nAyTTxF+dp+CYxZLdgRDQ+fKK7N31eHyrxZueoWMb86f3G\n" +
                "oNDN+9IiRNHtBLG9joVT+rnRh9fkeI/+co13uROEOKeJ2q7echTwt9SMdygW0Nz4\n" +
                "RNxXau+6ANkD+UyhztDoEdjE/W27HSz3ZBYqNt4qW0R9OxrOzIj4bMnqa3VTIO2q\n" +
                "2drSMTTlw7+mblySBukIhW7J204HUESe2O1+JcaK/eSlvuJjugk8HEn/36YSjyt3\n" +
                "v2IzzWL5o6yPCgBZJe802gehIiF4I17JZ+6uj4g3mFMYFAexhdZ0tJo/rIIK4i9m\n" +
                "ze7tNTTEAA/ytWjyHFOm+GRU5/aYc1t9BN7kaRr/2GSNCslUOCOVjoUu3PV/2nw5\n" +
                "QmZ2epdKCwjYB5+C3WEs+6yDEEzwggK/yNcr9fmFElKIwbzKEJ2YBTR6bT8bAG9n\n" +
                "MprsXuwKsZdR80s896dt0j8BbHvmaVZxzLuIwsIun3bqIV3cJmhjxD8o4ok/FklA\n" +
                "n7XpeeMMTMyt/5sZ8fGA9imuNUKiWJ1Xl8WzzExoK4g=\n" +
                "=8WMT\n" +
                "-----END PGP MESSAGE-----";
        ByteArrayInputStream bIn = new ByteArrayInputStream(ANONYMOUS_MESSAGE.getBytes(StandardCharsets.UTF_8));
        ByteArrayInputStream finalBIn = bIn;
        assertThrows(MissingDecryptionMethodException.class, () ->
                api.processMessage()
                        .onInputStream(finalBIn)
                        .withOptions(ConsumerOptions.get(api)
                                .addDecryptionKey(key)));

        bIn = new ByteArrayInputStream(ANONYMOUS_MESSAGE.getBytes(StandardCharsets.UTF_8));
        DecryptionStream dIn = api.processMessage()
                .onInputStream(bIn)
                .withOptions(ConsumerOptions.get(api)
                        .setAllowDecryptionWithMissingKeyFlags()
                        .addDecryptionKey(key));
        Streams.drain(dIn);
        dIn.close();
    }

    @Test
    public void testDecryptHiddenRecipientWithInteractiveCallback()
            throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey key = api.generateKey()
                .modernKeyRing("Alice <alice@example.org>", "sw0rdf1sh");

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        EncryptionStream eOut = api.generateMessage()
                .onOutputStream(bOut)
                .withOptions(ProducerOptions.encrypt(EncryptionOptions.get(api)
                        .addHiddenRecipient(key)));
        eOut.write("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        eOut.close();

        SecretKeyPassphraseProvider callback = new SecretKeyPassphraseProvider() {
            @Override
            public @Nullable Passphrase getPassphraseFor(@NotNull KeyIdentifier keyIdentifier) {
                return Passphrase.fromPassword("sw0rdf1sh");
            }

            @Override
            public boolean hasPassphrase(@NotNull KeyIdentifier keyIdentifier) {
                return true;
            }
        };
        SecretKeyRingProtector protector = SecretKeyRingProtector.defaultSecretKeyRingProtector(callback);

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        DecryptionStream dIn = api.processMessage()
                .onInputStream(bIn)
                .withOptions(ConsumerOptions.get(api)
                        .setMissingKeyPassphraseStrategy(MissingKeyPassphraseStrategy.INTERACTIVE)
                        .addDecryptionKey(key, protector));

        Streams.drain(dIn);
        dIn.close();
    }
}
