// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.signature;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.MessageMetadata;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.util.KeyRingUtils;

/**
 * Test if marker packets are being ignored properly.
 *
 * @see <a href="https://tests.sequoia-pgp.org/#Marker_Packet">Sequoia Test-Suite</a>
 */
public class IgnoreMarkerPacketsTest {

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

    @Test
    public void markerPlusDetachedSignature() throws IOException, PGPException {
        String sig = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "ygNQR1DCwTsEAAEKAG8FgmB9Y8YJEPv8yCoBXnMwRxQAAAAAAB4AIHNhbHRAbm90\n" +
                "YXRpb25zLnNlcXVvaWEtcGdwLm9yZ1j1pQ8+YA70OJUxn1bZxiCar4WPrLMuM2By\n" +
                "IITRjS1OFiEE0aZuGiOxgsmYD3iM+/zIKgFeczAAAOdzDACDhEptUvTFB7gx4YYG\n" +
                "fFCaPxpFNo8zKnlcB2g1cFkrKEpZ/2It3ozf0beL81TUaj7G0Z4iJVDR4ei6Zrdt\n" +
                "93GZRx+zQ6h3Wpj3TAi9mTHx5VRrMKK32o6VwRPuZy/KYCrst/eaM9LdhvAGsevR\n" +
                "aQfopMB1xS+/8ySGimOfD6NwUWuLiOUr9fvAf3UyhpZiHL4UJ2mB1rTbQJtM++yf\n" +
                "U48k+YsOVas/7B9qxlw3XsYvjVaFcTrKOj0lBn2uy2NMJje9dG+ll1lfdDkaqFFM\n" +
                "FNgiJqGeoQ0whIsURurhzcY5zgujEw0qXRLMblI+g+yw2THrNx07EArnr2WzVzIP\n" +
                "ifMu939eqm+mP0NKA1jVAPIIm92ZtIKD3+YzyczIepvLx4FwU1y5eAMotc76JrAg\n" +
                "VWR7+FdtSA63VnVvLBR6YX7C0PVGR6BJBLEOFcZjNoW/JhN6gpmUvJLeZkFogC+J\n" +
                "+J5EAJeGsE8/f/gi6pLtgAhjCNzH0qltOZsdJAfXqmd0NJ4=\n" +
                "=5tQ4\n" +
                "-----END PGP SIGNATURE-----\n";

        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(KEY);
        PGPPublicKeyRing publicKeys = KeyRingUtils.publicKeyRingFrom(secretKeys);
        String data = "Marker + Detached signature";
        PGPSignature signature = SignatureUtils.readSignatures(sig).get(0);

        InputStream messageIn = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(messageIn)
                .withOptions(ConsumerOptions.get()
                        .addVerificationCert(publicKeys)
                        .addVerificationOfDetachedSignature(signature)
                );

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        Streams.pipeAll(decryptionStream, outputStream);

        decryptionStream.close();
        MessageMetadata metadata = decryptionStream.getMetadata();
        assertTrue(metadata.isVerifiedSignedBy(new OpenPgpV4Fingerprint("D1A66E1A23B182C9980F788CFBFCC82A015E7330")));
    }

    @Test
    public void markerPlusEncryptedMessage() throws IOException, PGPException {
        String msg = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "ygNQR1DBwMwDfC+qTfk8N7IBC/4sXk4Al5Hdl38XCky41A1+HdJcDbXJ70/OY34M\n" +
                "QYvco/Yk5Lb5XXg2adtSlwM2C3d6a8JMwmU7qFP/pEDXijJiTD+NabbsWO2+BwGd\n" +
                "H9aTzAQhUj8PK4io5Q4SyxELosp9uO5XCkMkps5ev91mACwxm2p79tp7qkj8h4Q/\n" +
                "3j8Hc9Ea4o0WCKuTIO1p42nX7gHMaUPkmZqnUxhN7ZkUgC4AHsjDgteK0viUdkmg\n" +
                "aLza3TwN/e+vgnO8ypH1wBfdkvW+Ose5WPv587XGHZLsTQI6v2WeJo3K6KeuYXGI\n" +
                "lxx0kLnaUL+9TswQAfU1jeh3OEy/eUIsMXc+4miYmE0cg4QxfP3ERyeziJpkzYgJ\n" +
                "hGwK6cNfQiUXpWpyaAZ1vkCPEc074HIriGssq/CbkqUyUtbMzRuqfujZfMHiFkRc\n" +
                "VvHkR3gzvYlMFhSjHVM2Dx9wJWmQqStdeHKfnZg4fZXDD7/zy+xRPVQgQBWelSTR\n" +
                "4etbOP4OKLDX4LttGEPwy45KJvLSwZgBbU64o/RGNEbUt6dAXy3QeU5AkVR3h94f\n" +
                "sda0b04cn2ZAIAuvWdF5MsgxxACFYOIHwobHzZGW54TTpTMzLVKJo8XuOuGUQE58\n" +
                "jKJ+EiXZ3+TrItbhinUkZBdS59cleq2kNZ2dmTZ/ZkBwcOK1hH//Q8qrdLugm+h0\n" +
                "YD/OOKudZTEu93TISGb6VeeWsb8UVjncbb2S/A/9/huFgUNYu7zma4231Y6OFx2J\n" +
                "0tMVA+trKRWNhoacGwTl4mZnel42+IlgY6qVU+oTOCOtWNzuAeyj7PjnSMizv14u\n" +
                "PvVaWDJv61yxNrsnLRjUX0D+CcrYMn10672ICDKg+L9SiXe87saBmsegDYSQWwE9\n" +
                "WOtCWaEnKOSjD/Fewy/547dQJQihb9lG37wdM24t+J4qdkPkYKsUMhE3NcdrtLqJ\n" +
                "QO7qDhEpxoX8lloNcEAFo0p+HqgcKX86/AzDYHxoLHKqDOYUQEHcKCfwA7mSXBDV\n" +
                "JaOSO5Z2Jz+4HwvnD2ZgHP+qgctx87M5AgUQzlHm5mmBj3U3dvQQr6vIB4xtWKuy\n" +
                "DganN7X2Jb5wlODBntdlyoM7FUHE1GYsHI2HkGl6d3bGAcEQdy9NjQyiVuWBqbr8\n" +
                "OFDpFglcc70anHB091USc25LO23IhhXQ9ORalzULfoixf5lo6lmW3MPJGuYAhoIp\n" +
                "SA8m91mkrqvtBckHA7xE2LdDM5JbAFNPYZzvzz5pAgYTEQp1mJB25Va1G2QHZhos\n" +
                "dwvafpzRdOUaHM7lpvzTn3o3rM/Ntqfb6wn7GylsFYNpq+Rgtt6Mea68yTh+AeQ=\n" +
                "=VSZ3\n" +
                "-----END PGP MESSAGE-----\n";

        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(KEY);
        PGPPublicKeyRing publicKeys = KeyRingUtils.publicKeyRingFrom(secretKeys);
        String data = "Marker + Encrypted Message";

        InputStream messageIn = new ByteArrayInputStream(msg.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(messageIn)
                .withOptions(ConsumerOptions.get()
                        .addDecryptionKey(secretKeys)
                        .addVerificationCert(publicKeys)
                );

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        Streams.pipeAll(decryptionStream, outputStream);

        decryptionStream.close();
        assertArrayEquals(data.getBytes(StandardCharsets.UTF_8), outputStream.toByteArray());
        MessageMetadata metadata = decryptionStream.getMetadata();
        assertTrue(metadata.isVerifiedSignedBy(new OpenPgpV4Fingerprint("D1A66E1A23B182C9980F788CFBFCC82A015E7330")));
    }

    @Test
    public void markerPlusCertificate() throws IOException {
        String pubKeyBlock = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "\n" +
                "ygNQR1DGwM0EXaWc8gEMALlwv09ChAtMy6GNti9vg1y66jRt+aA9EXLBfneM+GgV\n" +
                "/hmDqa/+x45emB5xN05xW21/MLzJwgqu3dpBOLA4b9y1pHgGT+3prI0V91Q3EdaT\n" +
                "hYIrN3P/np9bY7QXbeohF3xRQmnkgiU3hEN1EK12FVAgC7O+nahXL8tpLaTFCgq+\n" +
                "mH/mlD/nCGqzKugRYMmhJXTI5vbkH+LCT+ktQWjKEMb1uPSQjMPGsSpb7sFryehx\n" +
                "CV5wwXdfkow3mSnbOtou/12UEGlZbjdeS2NwJmAzLbRKi6tpWZrwl78QLBRZhSIB\n" +
                "nEsiUy/0K6sQ63FTDo3dF060uZhlL24SefnLVSQXzyjw2S7z3S6ToGt7AXMnIsDH\n" +
                "nBFngXSpX/KrfpRZDQkH8BQaEdU90V/qmXp5rEHBPkZe9sFSJu1/xgjaiDlGyBNa\n" +
                "1d9Tt5tIZeuXlkylsDqZt+F3RHxo/FZ+YNaIg6EG5+EwK9QeHWwCkwpVme8h9/3/\n" +
                "QNxrfBu8sjBrdPgLKyF9PQARAQABzSFCb2IgQmFiYmFnZSA8Ym9iQG9wZW5wZ3Au\n" +
                "ZXhhbXBsZT7CwQ4EEwEKADgCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AWIQTR\n" +
                "pm4aI7GCyZgPeIz7/MgqAV5zMAUCXaWe+gAKCRD7/MgqAV5zMG9sC/9U2T3RrqEb\n" +
                "w533FPNfEflhEVRIZ8gDXKM8hU6cqqEzCmzZT6xYTe6sv4y+PJBGXJFXyhj0g6FD\n" +
                "kSyboM5litOcTupURObVqMgA/Y4UKERznm4fzzH9qek85c4ljtLyNufedoL2pp3v\n" +
                "kGtn7eD0QFRaLLmnxPKQ/TlZKdLE1G3u8Uot8QHicaR6GnAdc5UXQJE3BiV7jZuD\n" +
                "yWmZ1cUNwJkKL6oRtp+ZNDOQCrLNLecKHcgCqrpjSQG5oouba1I1Q6VlsP44dhA1\n" +
                "nkmLHtxlTOzpeHj4jnk1FaXmyasurrrI5CgU/L2Oi39DGKTH/A/cywDN4ZplIQ9z\n" +
                "R8enkbXquUZvFDe+Xz+6xRXtb5MwQyWODB3nHw85HocLwRoIN9WdQEI+L8a/56Au\n" +
                "Owhs8llkSuiITjR7r9SgKJC2WlAHl7E8lhJ3VDW3ELC56KH308d6mwOGZRAqIAKz\n" +
                "M1T5FGjMBhq7ZV0eqdEntBh3EcOIfj2M8rg1MzJv+0mHZOIjByawikbOwM0EXaWc\n" +
                "8gEMANYwv1xsYyunXYK0X1vY/rP1NNPvhLyLIE7NpK90YNBj+xS1ldGDbUdZqZee\n" +
                "f2xJe8gMQg05DoD1DF3GipZ0Ies65beh+d5hegb7N4pzh0LzrBrVNHar29b5ExdI\n" +
                "7i4iYD5TO6Vr/qTUOiAN/byqELEzAb+L+b2DVz/RoCm4PIp1DU9ewcc2WB38Ofqu\n" +
                "t3nLYA5tqJ9XvAiEQme+qAVcM3ZFcaMt4I4dXhDZZNg+D9LiTWcxdUPBleu8iwDR\n" +
                "jAgyAhPzpFp+nWoqWA81uIiULWD1Fj+IVoY3ZvgivoYOiEFBJ9lbb4teg9m5UT/A\n" +
                "aVDTWuHzbspVlbiVe+qyB77C2daWzNyx6UYBPLOo4r0t0c91kbNE5lgjZ7xz6los\n" +
                "0N1U8vq91EFSeQJoSQ62XWavYmlCLmdNT6BNfgh4icLsT7Vr1QMX9jznJtTPxdXy\n" +
                "tSdHvpSpULsqJ016l0dtmONcK3z9mj5N5z0k1tg1AH970TGYOe2aUcSxIRDMXDOP\n" +
                "yzEfjwARAQABwsD2BBgBCgAgFiEE0aZuGiOxgsmYD3iM+/zIKgFeczAFAl2lnPIC\n" +
                "GwwACgkQ+/zIKgFeczDp/wv/boLfh2SMF99PMyPkF3Obwy0Xrs5id4nhNAzDv7jU\n" +
                "gvitVxIqEiGT/dR3mSdpG0/Z5/X7kXrqH39E9A4nn628HCEEBxRZK6kqdSt1VplB\n" +
                "qdia1LFxVXY8v35ASI03e3OW6FpY7/+sALEn4r9ldCUjPBBVOk2F8bMBoxVX3Ol/\n" +
                "e7STXiK1y/pqUpjz6stm87XAgh5FkuZTS1kMPke1YO9RXusgUjVa6gtv4pmBtifc\n" +
                "5aMI8dV1Ot1nYKqdlsbdJfDprAf1vNEtX0ReRuEgx7PR14JV16j7AUWSWHz/lUrZ\n" +
                "vS+T/7CownF+lrWUe8kuhvM4/1++uzCyv3YwDb6T3TVZ4hJHuoTNwjQV2DwDIUAT\n" +
                "FoQrpXKM/tJcYvC9+KzDfg7G5mveqbHVK5+7i2gfdesHtAk3xfKqpuwbFQIGpaJ/\n" +
                "1FIrjGPNFN7nqI96JIkk4hyIw/2LaV0j4qAvJzJ4O8agGPQcIs7eBVoF7i5tWuPk\n" +
                "qOFfY9U0Ql3ddlHNpdkTZoAx\n" +
                "=TrY7\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";

        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(pubKeyBlock);
        assertEquals(new OpenPgpV4Fingerprint("D1A66E1A23B182C9980F788CFBFCC82A015E7330"), new OpenPgpV4Fingerprint(publicKeys));
        assertNotNull(publicKeys.getPublicKey(new OpenPgpV4Fingerprint("1DDCE15F09217CEE2F3B37607C2FAA4DF93C37B2").getKeyId()));
    }
}
