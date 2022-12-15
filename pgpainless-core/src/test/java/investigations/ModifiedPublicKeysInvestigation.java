// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package investigations;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.exception.KeyIntegrityException;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.key.util.KeyIdUtil;
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

    // created with exploit code by cure53.de
    private static final String INJECTED_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: F594 D7CC E7D0 1F15 1511  4395 C075 FD34 4B2A D41A\n" +
            "Comment: Juliet <juliet@montague.lit>\n" +
            "\n" +
            "lQPGBGGx9LYBCACxNiT7XMd6WXuZFJQ1RaQXixA+rw/VRiDueNUAkNs0BkJ92qpe\n" +
            "y5ljEiY2QY8O6hXxY7b2KF77jiuejGgz962+bIEhumtyPyN4oIML7tVWSyjN5pOd\n" +
            "bySAuw25752vB8Z0sDkENhidBF5yeNqeayqZOHvn1eFZsvJ2yV7J/k/H+5v1L2rH\n" +
            "CoO/lttbnnAH3cGqp9FkerejlE5HGld/LKhc2ViTayjJFWGAaAqpQJNYMRtJLTVG\n" +
            "c2jfYGv0j6na8/K118b/wqfKNU9O2/lzu0EpaJu6TpWZ02TeVht9NRnan6cmXH/Q\n" +
            "6yxJQLRn4a1MiAyYIoWs7BpBLAxh+Za/btAFABEBAAH+CQMCIJAO8LIQWNtgQSLB\n" +
            "YNMXgafrSc+E871154/yYeMPtn739smaedfrnI5nxHnuWb0pXLrfkWUIMjUwxnZ+\n" +
            "ktrVekc+RLhRWJqbO42/qdNzPlNwZFZXK6VRdT8DI23pOXkQiS7kXP3RwJzFw21q\n" +
            "emkOv26ZCWjnB4p/R4zpEYEAMtPDpdrIzlLU5laT9ashWDMUBA3ZSI9tH+jTmR+h\n" +
            "wvjVAXRNPf4Dhyh3sadorHHqgC8v6B5/Ou5fQoSIIn6FKB4lpvnXy/R/Gp8AhmRo\n" +
            "99Fdk1/XxovBVnTExO9upe/JVvu4XIQM+OxTdMyzCoFvoOGb+xhC2h/HrByouY+k\n" +
            "umSCq3XMQ4GVednXufWpFu3gapf2bnCzkgczwHrrXR6B3sNgXyKhS2yCPHfLsoFE\n" +
            "pkfpBQSSh5vpz5s5JWxdYWr415g8sUyva0XSwJN8QvzcLNgUBuSTDuSxGJ3j+ojl\n" +
            "E2isGyo0BhJkKp90bVnpBDJD2HAsHgFns5fA1xHuLzz86kEZwH852nhXQ64SzoJZ\n" +
            "Uy2+sA8afEkLm+YwcVj+6O6Kki4fqeEHVGB4aRSYbVWSLAuBfZqdIHR25xp1mp1J\n" +
            "lBFeo4F3/mXtY1fO5RrROmEsDz5O018jDbB7ZeLlROPV3s/F7Dvl6LC8omOHsinw\n" +
            "cV+FBEIXodrHvX55Lo+bxMDTXkQlaZjUvoce+GY0Sy1b/p2BMccG3DCfH7JH3VcM\n" +
            "cLpvLg+w0/o3mxEoSkCgohAcge1V4yUXDDGXNVs3UNvtzNemMjlUX6jlcC2WBeUu\n" +
            "YW0U9MxqI7pPx8+kXp0hzakr1ESRL65nFQoVYk0t8Jp4fQN79wOxt7JMnwHJ/ftg\n" +
            "y7czM2WdCHmxQgaBXX8SodKrwHfbm4armomgUCKBlcytQstMghfhNwUhu8F1l/Wt\n" +
            "9x8vyuVWUdpUtBxKdWxpZXQgPGp1bGlldEBtb250YWd1ZS5saXQ+iQFNBBMBCgBB\n" +
            "BQJhsfS2CZDAdf00SyrUGhahBPWU18zn0B8VFRFDlcB1/TRLKtQaAp4BApsDBZYC\n" +
            "AwEABIsJCAcFlQoJCAsCmQEAADvLB/9x66wNnA0O5MTIFIYf3HkMceHHq1eVgx88\n" +
            "NgItRXQh4Bg90C96SY6NWwoTkcZTGsmymNuuAzhCJwXFUr+mnoBODC6Qhoo4qr9D\n" +
            "vip1ekIGZUVGGRLQK6LHYtvQVKTVV4yih3CtrnP7jpN7lBVaTLCvhXqG1Ebez99Y\n" +
            "ne1DbHvIzHv6l9pf2rlUf8A6I8iBlPjWe3DLVKaMI3RjfMuRFI32UYnc+bBdcpVR\n" +
            "XYhXNrwj2OSTyplSBDAJfrIG5Kp+YD9Vip70csR+hZviNvyv7b/I9qfTbZw/RWBR\n" +
            "P6k/8mWU66NCnP4H4vqf5wak91T/KMI59rLRl8h4oIAXtSBHYGF1nKkEYbH0thII\n" +
            "KoZIzj0DAQcCAwRrGeShPKqoZYAey4qDWnMmMK//UAfP83Sf+hryPzpVa+/ywD0+\n" +
            "b+lU6W5AKoK6/9AySYE02XQdC8UawAhA9CtcAwEIB/4JAwIgkA7wshBY22DxMfI0\n" +
            "y3FeCOMZhTmZRkB1UgFWXeYGyd6gKI5jYFQyRCeogVZDven2aGzWiyEey+j20NbZ\n" +
            "KcS0S/YUvOIIDYN2wU+2yHG4iQEzBBgBCgAdBQJhsfS2Ap4BApsMBZYCAwEABIsJ\n" +
            "CAcFlQoJCAsACgkQDG4T6nONbigLjwf9EjyKrAhdrznmC2+vVoJSq9DHqLtpiGid\n" +
            "b3ImJ5REKzXs8JVyyRLj0dQMOx+D6lA5xmxMjMKAFu+QKXFv1khDQofz3x+GbHDu\n" +
            "Q9jROzUpErcXmTHinRE3lA2ogd0uPbQcVvG8zBxy4GuEZgXoEgYHawijnXpTdNeh\n" +
            "oeLWpnx/3UQlNbQR8oSj2InG96C8fHyOBEkGdY2KweI/BU+7ui3JfSoHuOiWnsa3\n" +
            "d0bptkmD7d3grIuq8oHZBkOCPOYkZbYY4WFh5L01W95Hrzf1yEjqyzvVatpiSrMK\n" +
            "JIsbPcS2yyN9uXP54vwsq7D/mx6CMV1XcpZGwsT8o35Txa00MoXRo5ypBGGx9LYS\n" +
            "CCqGSM49AwEHAgME8pVmU/csKSjqhvuJ0siOaf1K91BWQ4/piZ3Fv3zrcrk2sl15\n" +
            "ThOU0OyvPnUf77yDrW5NRv2gnFDQNpQq2x3spAMBCAf+CQMCIJAO8LIQWNtgb47o\n" +
            "8lBl7RalDXipU01bB59q2wqHVKvF3+fPQ6+c0WdT6ZxZKmV4MXnaVpx4kDozYSf8\n" +
            "E7Sj7PwFdUGcP2/i8Y/NYlRErIkBMwQYAQoAHQUCYbH0tgKeAQKbDAWWAgMBAASL\n" +
            "CQgHBZUKCQgLAAoJEAxuE+pzjW4oKb0H/ictFOa+m1gbxuQ4WW81/Yxt4sprsa0p\n" +
            "rf7KmUAKnChcFEswtmgfFltqgo6CZssWm9bp/bsqksONUHDF1ElU1kiwKQdEau38\n" +
            "Ufj7tzdBmlZuFAokHnTG+pQpyJP0w/unFZD++QU7hjXN4if/q3q2kZ+JvYpCQ1yI\n" +
            "mzUkYkTbP94PBsVO7SDWnFHsvGefXwacYvV/W+OvRLFuQVR53xqbn6wGtD61t8nD\n" +
            "XIFyxOECyp+E22nkeeI3betGSq0LeExPbjEUpVWWhZ4Rt2UkkmaME9V717vl5x4s\n" +
            "L24DZ9kR5ToqBF682oWOXe4H18WLeBQqCI7jpx/Mx95oC+Xsm7F/K4qcqQRhsfS2\n" +
            "EggqhkjOPQMBBwIDBAc4vOQ08Z6IDj/7JSKomFsJtE++n1Bb22QdiQWnrQ/t0B2Y\n" +
            "53woGsMh+KYDInE2XET7xpl5Ufscy2X3AMnFZlEDAQgH/gkDArgFuyIOfkRHYHi3\n" +
            "iHCxic2RPt8FkLlQMjg66rKPv7sAye1tJG0QeEBOvDeTq0f64OddF7BuBe5t/wUg\n" +
            "qABg8nj8tku9Tj8vUjnowraha5+JATMEGAEKAB0FAmGx9LYCngECmwwFlgIDAQAE\n" +
            "iwkIBwWVCgkICwAKCRDAdf00SyrUGmfyB/9aVNKuDTH6yRZWPYoypA6UCChvJb38\n" +
            "K4aW2DexljtmuA7i4lbomFkltbbEiZOw2+Q1uan2gVrhwPIh9aRFZH4H4djlVzEh\n" +
            "Xg4G51N548Ye4xWHw7LLttoRghfUB4skgAxvuj5eBRfQJBM4/qm1V3QXGkbYPKuD\n" +
            "QDgApRZNt5Cal4uD+dj7rxhq+RUC0KbFKMXQoGtgqeeKZ0AtLgjxDR/7NXo21YS2\n" +
            "6hEQTtowHm3gFQPyC9LHZbnlp6lmz3gVTeR79kQkbwGjeFZtnbVboSwIYuurq4vc\n" +
            "gHJaPa2iv3d1AmhtqLXIGfVPuW5+ldPDIeXGcVa1QWy+tPqf+d2V0O3SnKkEYbH0\n" +
            "thIIKoZIzj0DAQcCAwSdwn1X0Iad1ljcVzuhCLfQgmfe6vslc/DzTrXK9zM/JeZ7\n" +
            "pYQZybmkIqVr+azNDGR5A1queAf9Z6jgbPSR2uQlAwEIB/4JAwK4BbsiDn5ER2Aj\n" +
            "XvTPCUUX6hL8kG3mybW/Y9B3GzMSAUjYm0waLsvmu8f/miOqZ/sprMQKhpFE76f7\n" +
            "1NvDh2ZjMwVO3BOs2PRfnAOPE8KXiQEzBBgBCgAdBQJhsfS2Ap4BApsMBZYCAwEA\n" +
            "BIsJCAcFlQoJCAsACgkQwHX9NEsq1BoVPQf/QY4yo51KqtpxxZ3DGc+A11kcQC2M\n" +
            "GSJR7kMAlGY/wMhjVVVhdvU0d1tNUI//qil/xjdCHggGnIC0k6Gn64j2KDbwGn/n\n" +
            "ptCO7X4w9r/dHjWe0s7OSVBKs8fF7/7gX3eejQ3IXV6CrwIZ1nP5Ugd5ywX2ciLE\n" +
            "T1bWeJWPaNV+dz+ZzZqgd/vM8dmDUw3bfolJRdxdRIzJyq6TgdG/U8Ae2TkGEHyM\n" +
            "a3ZBwq51y2Y6z9WuangJ00RFjnQOZvXsueJKepLPTioo4TJXaYkD7VOYNxFIJQPt\n" +
            "7Yv10ZA5XaaMrWtWG6vei9Ji53/bYNRVqs5jcNS168zeMOYgwrEaDbpU3g==\n" +
            "=WEYQ\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    @Test
    public void assertModifiedDSAKeyThrowsKeyIntegrityException() throws IOException {
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword("12345678"));
        PGPSecretKeyRing dsa = PGPainless.readKeyRing().secretKeyRing(DSA);

        PGPainless.getPolicy().setEnableKeyParameterValidation(true);
        assertThrows(KeyIntegrityException.class, () ->
                UnlockSecretKey.unlockSecretKey(dsa.getSecretKey(KeyIdUtil.fromLongKeyId("b1bd1f049ec87f3d")), protector));
        assertThrows(KeyIntegrityException.class, () ->
                UnlockSecretKey.unlockSecretKey(dsa.getSecretKey(KeyIdUtil.fromLongKeyId("f5ffdf6d71dd5789")), protector));
        PGPainless.getPolicy().setEnableKeyParameterValidation(false);
    }

    @Test
    public void assertModifiedElGamalKeyThrowsKeyIntegrityException() throws IOException {
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword("12345678"));
        PGPSecretKeyRing elgamal = PGPainless.readKeyRing().secretKeyRing(ELGAMAL);

        PGPainless.getPolicy().setEnableKeyParameterValidation(true);
        assertThrows(KeyIntegrityException.class, () ->
                UnlockSecretKey.unlockSecretKey(elgamal.getSecretKey(KeyIdUtil.fromLongKeyId("f5ffdf6d71dd5789")), protector));
        PGPainless.getPolicy().setEnableKeyParameterValidation(false);
    }

    @Test
    public void assertInjectedKeyRingFailsToUnlockPrimaryKey() throws IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(INJECTED_KEY);
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword("pass"));

        PGPainless.getPolicy().setEnableKeyParameterValidation(true);
        assertThrows(KeyIntegrityException.class, () ->
                UnlockSecretKey.unlockSecretKey(secretKeys.getSecretKey(), protector));
        PGPainless.getPolicy().setEnableKeyParameterValidation(false);
    }

    @Test
    public void assertCannotUnlockElGamalPrimaryKeyDueToDummyS2K() throws IOException {
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword("12345678"));
        PGPSecretKeyRing elgamal = PGPainless.readKeyRing().secretKeyRing(ELGAMAL);

        assertThrows(PGPException.class, () ->
                UnlockSecretKey.unlockSecretKey(elgamal.getSecretKey(KeyIdUtil.fromLongKeyId("5f04acf44fd822b1")), protector));
    }

    @Test
    public void assertUnmodifiedRSAKeyDoesNotThrow() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .simpleRsaKeyRing("Unmodified", RsaLength._4096, "987654321");
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword("987654321"));

        for (PGPSecretKey secretKey : secretKeys) {
            assertDoesNotThrow(() ->
                    UnlockSecretKey.unlockSecretKey(secretKey, protector));
        }
    }

    @Test
    public void assertUnmodifiedECKeyDoesNotThrow() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .simpleEcKeyRing("Unmodified", "987654321");
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword("987654321"));

        for (PGPSecretKey secretKey : secretKeys) {
            assertDoesNotThrow(() ->
                    UnlockSecretKey.unlockSecretKey(secretKey, protector));
        }
    }

    @Test
    public void assertUnmodifiedModernKeyDoesNotThrow() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("Unmodified", "987654321");
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword("987654321"));

        for (PGPSecretKey secretKey : secretKeys) {
            assertDoesNotThrow(() ->
                    UnlockSecretKey.unlockSecretKey(secretKey, protector));
        }
    }
}
