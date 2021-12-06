// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package investigations;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.exception.KeyIntegrityException;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.Passphrase;

public class ModifiedPublicKeysInvestigation {

    private static final String DSA = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: OpenPGP.js VERSION\n" +
            "Comment: https://openpgpjs.org\n" +
            "\n" +
            "xcLBBF7gtMkRCAC3vDJOsVLxDrh78Mm8hgwpxIPJp47p2AZH2DPrv0hqigc7\n" +
            "zqaF9DGZpovOEag3t192bIxY81Nv7HKsjdhMhPnpXY5xrWhcZm2qYWQ37Hy6\n" +
            "GBQCYJpYWIz8y1OohbK72lvoOp8zfLY5L6QtQvenZFWLZEhM27uY0mvEwZhK\n" +
            "w8BnZinqviupyL58pDG2nSvJZBC3JSPpRUt9m/91aKdF1bM2EeL8PSExfRaD\n" +
            "YrDEcWhtXR+WOHMNNjIzCJH1bYGXzokMYbgX5TfbTAqUvxWlbpSPe+jTDDei\n" +
            "xCZ1qNiYKJARb9Du8KDaFu7D1/DlE+Y6xQY8QxuF5GIig8/j9DXMBGuHAQCx\n" +
            "NS8+e0LZ63YHiPWHDAPeGztx2QoLRoy26LUC+gw9Fwf+MiaaKCc8IAom8nSV\n" +
            "JUW6BYBhxAQ4oXja/rIXfjfHMTpHyAv2D6rzYWs4MTpjwq/bp+f61PZA7LF4\n" +
            "hI2fvZIh5A+7pkzhDQ3vsR0JlHCN7zjdyDkecqXoxF2Li+0A1iofcC9iApFf\n" +
            "hVeGhEETtCJ75MjTcG4HH9icSsIeO99ez6fbw8xtD4cm8/cCZviRJzY2NWaP\n" +
            "OUFee4DoHXBqJvmA9tZ7GCa1yJj3QNcMSV4+g5bom/kbiJWE3Kxvt3vbt9HY\n" +
            "uutjK6t95VoL8Gn/KeRmcafyvHb5v03IJOZYtWVtMnnhzp4eULB5NIMnNO+j\n" +
            "2Fp0BT2hG9tRuiR7NhT6pUAi2AgAgbYnNdmQbUw8SOszWckiI5Cy43jhuR7U\n" +
            "8yQKxLK2sGATyEbORgo1R5ykMsOm5stviqSleihqaij01dtrufhNRNuW/hHy\n" +
            "yhEzMLJCjOQ2K1OOlavmNPnUvBOKSaHIIGxtDf6kUhuXTUZeuoX+SqzemlEN\n" +
            "w6dRopm3o98wkLmf9XZIIe3YzhnIqnXrVChMJR1Tb5uZ2cgL+J4mhTw4XE6G\n" +
            "9S/7VG+033wOH4vBNNzr/oeEDqEWbnvsK0z2LQhMqS3oEMGtiBuUBqrSQ4Ol\n" +
            "pKa6uN1YSbFhPGFdVjyUTsDJodQKXCAcDiuXkxqhU3yTps/9pdQTFV+nHnFo\n" +
            "UQ+q6qcKuf4JAwiezB8yRqiUDwDYXJPqetnfSfb8HJK94SobBbpnnJWmimTo\n" +
            "5xXmh8ADOeNPFvoUBAHLVlaOHQ+RxvH5+myTWgQGUCFwx0hw/FKYwf5/TJoL\n" +
            "zRNhIDxkc2FAZWxnYW1hbC5jb20+wo8EEBEIACAFAl/0Q7UGCwkHCAMCBBUI\n" +
            "CgIEFgIBAAIZAQIbAwIeAQAhCRCxvR8Ensh/PRYhBA/hAsFZyBjvLX2ffrG9\n" +
            "HwSeyH89eTkBAI3qhlbtwKsmGKON1vNOlMoowQdM4vQ79Thff+cTCjseAQCP\n" +
            "KtVp3MBiGFVGL9WWkLWZ4pA/B5i3/j34AgI+ko4clMfCqgRe4LTJEAgAt7wy\n" +
            "TrFS8Q64e/DJvIYMKcSDyaeO6dgGR9gz679IaooHO86mhfQxmaaLzhGoN7df\n" +
            "dmyMWPNTb+xyrI3YTIT56V2Oca1oXGZtqmFkN+x8uhgUAmCaWFiM/MtTqIWy\n" +
            "u9pb6DqfM3y2OS+kLUL3p2RVi2RITNu7mNJrxMGYSsPAZ2Yp6r4rqci+fKQx\n" +
            "tp0ryWQQtyUj6UVLfZv/dWinRdWzNhHi/D0hMX0Wg2KwxHFobV0fljhzDTYy\n" +
            "MwiR9W2Bl86JDGG4F+U320wKlL8VpW6Uj3vo0ww3osQmdajYmCiQEW/Q7vCg\n" +
            "2hbuw9fw5RPmOsUGPEMbheRiIoPP4/Q1zARrhwf+MiaaKCc8IAom8nSVJUW6\n" +
            "BYBhxAQ4oXja/rIXfjfHMTpHyAv2D6rzYWs4MTpjwq/bp+f61PZA7LF4hI2f\n" +
            "vZIh5A+7pkzhDQ3vsR0JlHCN7zjdyDkecqXoxF2Li+0A1iofcC9iApFfhVeG\n" +
            "hEETtCJ75MjTcG4HH9icSsIeO99ez6fbw8xtD4cm8/cCZviRJzY2NWaPOUFe\n" +
            "e4DoHXBqJvmA9tZ7GCa1yJj3QNcMSV4+g5bom/kbiJWE3Kxvt3vbt9HYuutj\n" +
            "K6t95VoL8Gn/KeRmcafyvHb5v03IJOZYtWVtMnnhzp4eULB5NIMnNO+j2Fp0\n" +
            "BT2hG9tRuiR7NhT6pUAi2Af/Ww4X+sMiX5so7CZzIi0cMaYFaO4QD3zOFATg\n" +
            "lpqEmyYIT0CdQrr3fxJfpVgLZKzRkacecbJD1yBg75x6DlEPf4ScClygymzQ\n" +
            "W0YBJ4/aQBBwn0uBGJUsvU5vBjN4uNNvoKkT4PGPGWw4duzTjwAg9UPirsQf\n" +
            "DOgSBtA8VJpCvY8uZwu1rMybSitgo3SWnsmB0Sfk7FpPcWx5wbuF5aWENiBG\n" +
            "TcecGrWHlB7mHDJ2VKnqvsn0Ned13lgCrbVri5WcodB30IXAK1xknQD+SBiL\n" +
            "Ere8Wxf5Ge/dsi9ygdin0lwfveLHmreO9rLOLXA40q1bfVMguUcx+oSQHad1\n" +
            "YXft1/4JAwgOjqeNUGKHFQDYG8nEzqEAT8zs6r+WYXwJAWHjwO4kFQjxy6Fv\n" +
            "dv9JnfXweIWvrfaoytJ4PX9yy0y2EHyMmH2p+ZXGBSphERJjdzdgjZU95cGF\n" +
            "VMpOoyoUpg/CeAQYEQgACQUCX/RDtQIbDAAhCRCxvR8Ensh/PRYhBA/hAsFZ\n" +
            "yBjvLX2ffrG9HwSeyH8925EBAJ5ILo/q8Z01vCiCdEV/i2nMEevI7EHG5DtM\n" +
            "RuvLdJPtAP9VND4sdnrXUXoUn6OgUmKoV0KKcTUPEnMqQ8QgfVDEJA==\n" +
            "=p9kX\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    private static final String ELGAMAL = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: OpenPGP.js VERSION\n" +
            "Comment: https://openpgpjs.org\n" +
            "\n" +
            "xcJ2BF7gtMkRCACn33NmdVvNmFRs7wp/EYbfFo3eHygwJDx93cpi++YDWf57\n" +
            "Jz0A0WbihN3CYQuO/CE1sqJfpktc4Q0yhNwAMX49xxfcl6mwWawAhianG1Tj\n" +
            "zM5L0YY6Qipi+L8F4cRk/u4leElAPySN/X7Ami3HGcVoU+BJ03ssnz0iiBb0\n" +
            "mA4gPDRBueXNSQdI5TG6qEANCCRNLvg53p8G9BQRCXs0SunorUFc9BSOqcgX\n" +
            "IH+dkzjjvJPFVCMvcsp5L9nsJ9demtSwWsJrlBkA2UmgZ/PVItvxSGSukP3c\n" +
            "5+JKUaIFsAjBWwMsJcBDvq6FYBL1e7IO/ZBsl/5TpFtWtCYEbNAnmjg3AQCz\n" +
            "ZGzliaDRrxn1wREz13aQ760Tzno+X9O54Ef6Ya+Nywf9HQh5LEdpQJio7rYp\n" +
            "6/Heu8j0dqgqBs6SNHxVQPuiKgpnTOCEE3eXN4FnZ1/PyQOyMdPkIoi4p36Y\n" +
            "iMBnxJBRHG0QAFqVdiP4Yzqv+K07De/De569okE43CHlgJN5r+ZU+NVGT5vW\n" +
            "jN6izoK0H1IjIkLU4ZNbVEOuEVRI///MZ++OTEtEyv92sIFFfbKa5efazsQu\n" +
            "xBm1w8T2W9avcUwEdV/iErNqRfZ1Ty+WMFNyTlFpEBdNkSx6QQsHw6lAfWjR\n" +
            "ScEf3HhpaIEvZ3xwYvUeM4/h+H+tvy8MSF5jNuw4UV7dCiG4cf3vrTWHoTDh\n" +
            "3iYwTYZNB/NcU37gu7mdEoz/yQf/Tn0pExWBO9qYjPmsOcviZX/2dXJv4E85\n" +
            "eHRO8NpliXsNXLypZQXYcMIOT60LYDIHJnideMapa84xkT2eNK3jdK/yVbkO\n" +
            "X/9/UvvYkruMv4d05jEN3oTVGeBbeplgbnnbmOI0mRhm8nML3+4+76p+zTH3\n" +
            "5yXHhbe5e8vN9HLDSaxJMBT9YLSzi4B3qYUbN3GP6xxpBdsUNC4uPUWrgJZe\n" +
            "ruz1ItTEHc9zecPoBjZ2zsNBfYKa4IBbPC0Hdu5xhrlUUlDQfYWpLbtuuxgz\n" +
            "2W5l8FZpHH8DAQ/pv5TMuMEr5cGK5N7/D7VIILsl4zRSrZfpLlN3p/bTrYaq\n" +
            "vBLy7kSdeP4JZQBHTlUBzRNhIDxkc2FAZWxnYW1hbC5jb20+wo8EEBEIACAF\n" +
            "Al+uqvIGCwkHCAMCBBUICgIEFgIBAAIZAQIbAwIeAQAhCRBfBKz0T9gisRYh\n" +
            "BJsPXWgA3qU0mfRVx18ErPRP2CKxG/cA/0EMxk/JebLdXJuHCdFfmuefSLJx\n" +
            "3r/T5YAC2C2J3NoUAQCzL8sEY3GPjwLG3usTC03OiCeyaS3cMSodpJr38TwX\n" +
            "U8fCqgRe4LTJEAgAt7wyTrFS8Q64e/DJvIYMKcSDyaeO6dgGR9gz679IaooH\n" +
            "O86mhfQxmaaLzhGoN7dfdmyMWPNTb+xyrI3YTIT56V2Oca1oXGZtqmFkN+x8\n" +
            "uhgUAmCaWFiM/MtTqIWyu9pb6DqfM3y2OS+kLUL3p2RVi2RITNu7mNJrxMGY\n" +
            "SsPAZ2Yp6r4rqci+fKQxtp0ryWQQtyUj6UVLfZv/dWinRdWzNhHi/D0hMX0W\n" +
            "g2KwxHFobV0fljhzDTYyMwiR9W2Bl86JDGG4F+U320wKlL8VpW6Uj3vo0ww3\n" +
            "osQmdajYmCiQEW/Q7vCg2hbuw9fw5RPmOsUGPEMbheRiIoPP4/Q1zARrhwf+\n" +
            "MiaaKCc8IAom8nSVJUW6BYBhxAQ4oXja/rIXfjfHMTpHyAv2D6rzYWs4MTpj\n" +
            "wq/bp+f61PZA7LF4hI2fvZIh5A+7pkzhDQ3vsR0JlHCN7zjdyDkecqXoxF2L\n" +
            "i+0A1iofcC9iApFfhVeGhEETtCJ75MjTcG4HH9icSsIeO99ez6fbw8xtD4cm\n" +
            "8/cCZviRJzY2NWaPOUFee4DoHXBqJvmA9tZ7GCa1yJj3QNcMSV4+g5bom/kb\n" +
            "iJWE3Kxvt3vbt9HYuutjK6t95VoL8Gn/KeRmcafyvHb5v03IJOZYtWVtMnnh\n" +
            "zp4eULB5NIMnNO+j2Fp0BT2hG9tRuiR7NhT6pUAi2Af/Ww4X+sMiX5so7CZz\n" +
            "Ii0cMaYFaO4QD3zOFATglpqEmyYIT0CdQrr3fxJfpVgLZKzRkacecbJD1yBg\n" +
            "75x6DlEPf4ScClygymzQW0YBJ4/aQBBwn0uBGJUsvU5vBjN4uNNvoKkT4PGP\n" +
            "GWw4duzTjwAg9UPirsQfDOgSBtA8VJpCvY8uZwu1rMybSitgo3SWnsmB0Sfk\n" +
            "7FpPcWx5wbuF5aWENiBGTcecGrWHlB7mHDJ2VKnqvsn0Ned13lgCrbVri5Wc\n" +
            "odB30IXAK1xknQD+SBiLEre8Wxf5Ge/dsi9ygdin0lwfveLHmreO9rLOLXA4\n" +
            "0q1bfVMguUcx+oSQHad1YXft1/4JAwiUPMqEIUCgsACIlVF2VExLGCEnlGvC\n" +
            "r6xO8HZyFotZCvTaqdpAeEwR3j8iPuLHZ6UM4qM0iWKGnXwvwnXQb9gNCQjv\n" +
            "sQi3ZA0XU9VyF0Br2pWC8O1pSzsfR6nCeAQYEQgACQUCX66q8gIbDAAhCRBf\n" +
            "BKz0T9gisRYhBJsPXWgA3qU0mfRVx18ErPRP2CKxAT4A/1Me/0H9uMxhqeL8\n" +
            "IZ2L59G9ofFMud0g1eUzYaAN+XLtAQCkR7SCspq4PWYYY+YcnhWWMPAA1TM6\n" +
            "TsMBqN9H5d+2XQ==\n" +
            "=lI+G\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    @Test
    public void investigate() throws IOException {
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword("12345678"));

        PGPSecretKeyRing dsa = PGPainless.readKeyRing().secretKeyRing(DSA);
        PGPSecretKeyRing elgamal = PGPainless.readKeyRing().secretKeyRing(ELGAMAL);

        // CHECKSTYLE:OFF
        for (PGPSecretKey secretKey : dsa) {
            try {
                UnlockSecretKey.unlockSecretKey(secretKey, protector);
                System.out.println("No KeyIntegrityException for dsa key " + Long.toHexString(secretKey.getKeyID()));
            } catch (KeyIntegrityException e) {
                System.out.println("KeyIntegrityException for dsa key " + Long.toHexString(secretKey.getKeyID()));
            } catch (PGPException e) {
                System.out.println("Cannot unlock dsa key: " + e.getMessage());
            }
        }

        for (PGPSecretKey secretKey : elgamal) {
            try {
                UnlockSecretKey.unlockSecretKey(secretKey, protector);
                System.out.println("No KeyIntegrityException for elgamal key " + Long.toHexString(secretKey.getKeyID()));
            } catch (KeyIntegrityException e) {
                System.out.println("KeyIntegrityException for elgamal key " + Long.toHexString(secretKey.getKeyID()));
            }catch (PGPException e) {
                System.out.println("Cannot unlock elgamal key: " + e.getMessage());
            }
        }
        // CHECKSTYLE:ON
    }
}
