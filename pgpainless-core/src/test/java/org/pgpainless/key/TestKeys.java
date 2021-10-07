// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Date;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.pgpainless.util.Passphrase;

public class TestKeys {

    private static final KeyFingerPrintCalculator calc = new BcKeyFingerprintCalculator();
    private static PGPSecretKeyRing julietSecretKeyRing = null;
    private static PGPPublicKeyRing julietPublicKeyRing = null;
    private static PGPSecretKeyRing romeoSecretKeyRing = null;
    private static PGPPublicKeyRing romeoPublicKeyRing = null;
    private static PGPSecretKeyRing emilSecretKeyRing = null;
    private static PGPPublicKeyRing emilPublicKeyRing = null;
    private static PGPSecretKeyRing cryptieSecretKeyRing = null;
    private static PGPPublicKeyRing cryptiePublicKeyRing = null;

    private static PGPSecretKeyRingCollection julietSecretKeyRingCollection = null;
    private static PGPPublicKeyRingCollection julietPublicKeyRingCollection = null;
    private static PGPSecretKeyRingCollection romeoSecretKeyRingCollection = null;
    private static PGPPublicKeyRingCollection romeoPublicKeyRingCollection = null;
    private static PGPSecretKeyRingCollection emilSecretKeyRingCollection = null;
    private static PGPPublicKeyRingCollection emilPublicKeyRingCollection = null;
    private static PGPSecretKeyRingCollection cryptieSecretKeyRingCollection = null;
    private static PGPPublicKeyRingCollection cryptiePublicKeyRingCollection = null;

    public static final String JULIET_UID = "xmpp:juliet@capulet.lit";
    public static final long JULIET_KEY_ID = -5425419407118114754L;
    public static final String JULIET_FINGERPRINT_STRING = "1D018C772DF8C5EF86A1DCC9B4B509CB5936E03E";
    public static final OpenPgpV4Fingerprint JULIET_FINGERPRINT = new OpenPgpV4Fingerprint(JULIET_FINGERPRINT_STRING);

    /**
     * Public key of xmpp:juliet@capulet.lit.
     */
    public static final String JULIET_PUB = "" +
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "mQENBFrxov4BCAChZwPrBxxIlwzpieR5T2pnaOZLWH0WqSON6rVjvfbJHWdDi3Th\n" +
            "remHW4gg4IBSTXkVFDIeQNVcOvGNgMg3Oe/x0I6FK12jrw9prycmjFxQ7A0ix7ZG\n" +
            "UkTF5jITgzJbkH100gYfXtZsfTyvgISSAT//6vvvQPZ3zCr09XvAG0CyQ1BhULsv\n" +
            "mVRe4Oh5b0VK4kLdv+GiA/T+49UKZj6lne9Vdti16ZIj7teVCbicfdhpTzsjur42\n" +
            "r8ptouKAuyFPw9KnGNwVlIiv5jt/Kit/LoOBenh74sitsCXq8IQ9kKp/eNt8TF4u\n" +
            "D4IGpxnJfB8XCiixYHoFEajmQBVJXNYtvoPvABEBAAG0F3htcHA6anVsaWV0QGNh\n" +
            "cHVsZXQubGl0iQFOBBMBCAA4FiEEHQGMdy34xe+GodzJtLUJy1k24D4FAlrxov4C\n" +
            "Gy8FCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQtLUJy1k24D6H7AgAoTjx4ezc\n" +
            "A83NeOY3tMHVQTM7hKuy0wMcSzQgVgJmhLYRZS8r+FocPZua/eke49GPhe2yozvl\n" +
            "ByWHtotklQeJiwOKxuPKMzneVA1ZK3/9LdGvtZlHMcAkEKDhit8HIaEcsFd4Z1re\n" +
            "EhF2lyvY/E+rrx9YxV0QjisSWV2dSptv6FeGSztr9e5E+Head6hEQhsugiTVRF+1\n" +
            "6mG90te0WGQ9YNiJ2FJovx5kBLTTuhwUz8Oacqihd2+RDDI5p3wJoogVL31aNb4n\n" +
            "c7dGo8ieJPHGlkBsOfmreSxijTodZz9MXsgcx7b//u0uQryViJoZHWbtnXOFjjNc\n" +
            "GWBtS084NKWl9w==\n" +
            "=ecwX\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    /**
     * Private key of xmpp:juliet@capulet.lit.
     */
    public static final String JULIET_SEC = "" +
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "lQOYBFrxov4BCAChZwPrBxxIlwzpieR5T2pnaOZLWH0WqSON6rVjvfbJHWdDi3Th\n" +
            "remHW4gg4IBSTXkVFDIeQNVcOvGNgMg3Oe/x0I6FK12jrw9prycmjFxQ7A0ix7ZG\n" +
            "UkTF5jITgzJbkH100gYfXtZsfTyvgISSAT//6vvvQPZ3zCr09XvAG0CyQ1BhULsv\n" +
            "mVRe4Oh5b0VK4kLdv+GiA/T+49UKZj6lne9Vdti16ZIj7teVCbicfdhpTzsjur42\n" +
            "r8ptouKAuyFPw9KnGNwVlIiv5jt/Kit/LoOBenh74sitsCXq8IQ9kKp/eNt8TF4u\n" +
            "D4IGpxnJfB8XCiixYHoFEajmQBVJXNYtvoPvABEBAAEAB/4jMbXagW3q7DkOEZnm\n" +
            "0+jVTLvu0QhRsScGEphj+++8sfMq+NVPQp9p+w0Hcjy49ZjB/mnhS+zaVCYI33yJ\n" +
            "AlKubXYuVqLwBsO7HUzRrIiSwq4ol9jIo7bIWmYv+As6iRq6JvPb0k+6T2K0uDbw\n" +
            "KWKduM0fwhAcVkJFsOO/o5GrbQaJc3oioFk8uFWTnO+FPBRTJ9oTlVG2M/tEatZK\n" +
            "gl7I8Ukl0YYruCNUFKZ0tvO8HqulxBgUbGPBer1uOlfUD4RXdc8/PUiFKNo48XSu\n" +
            "ZUEAZKGbFBjuX5Z8ha7+sUMEYEt70qlbkiLQxgHKAmpyridAk3q/SB3y2VB8Ik7I\n" +
            "gpExBADInzLROYuUcXqmty+znVwm6nRIB75JBAy778zgIxx1v0O3QlVnR+YI8gJM\n" +
            "mQ/9pD6LyP9hktWDmJxG8tX+kSuIp3wNJc5EMeXtCCmkUW0CP1gUhAbNW3MezKa5\n" +
            "II5IhE9RgIsYqSU8ZgeIh72ON8XTp8i/wGipCXvJPggSAMXukQQAzfRmtLW+JHEK\n" +
            "B8ETIYh8IUjXJ6TVlmuBwZ0eXjCpqy9arJi6tacesDJwnL3sqOMQWUmqGsCGSKA5\n" +
            "cLITkVsxX/htIq8GFyludjg8t4Nr+fOGfChEq8QE0PHE2CgskQMHpfHvfIdnwKve\n" +
            "Fg2Q8twoMw849O6PF3k/848Z65lDin8EAMDbuPWL7KU2sWeqvDEuoulS5K1gsq8X\n" +
            "p3Od3+f0OG8YViMjKcVlSKHVvdlK4dlsccJrJJx6VzotV47LsmvVbzDwUE//MYq7\n" +
            "QwwQetZbpdQZDysSGVqHMTuAg/1pr2u5rqh4cFqCYatgZwinEI2TQMXEqnSc+mj8\n" +
            "xp/LNq5BZZQuO4y0F3htcHA6anVsaWV0QGNhcHVsZXQubGl0iQFOBBMBCAA4FiEE\n" +
            "HQGMdy34xe+GodzJtLUJy1k24D4FAlrxov4CGy8FCwkIBwIGFQoJCAsCBBYCAwEC\n" +
            "HgECF4AACgkQtLUJy1k24D6H7AgAoTjx4ezcA83NeOY3tMHVQTM7hKuy0wMcSzQg\n" +
            "VgJmhLYRZS8r+FocPZua/eke49GPhe2yozvlByWHtotklQeJiwOKxuPKMzneVA1Z\n" +
            "K3/9LdGvtZlHMcAkEKDhit8HIaEcsFd4Z1reEhF2lyvY/E+rrx9YxV0QjisSWV2d\n" +
            "Sptv6FeGSztr9e5E+Head6hEQhsugiTVRF+16mG90te0WGQ9YNiJ2FJovx5kBLTT\n" +
            "uhwUz8Oacqihd2+RDDI5p3wJoogVL31aNb4nc7dGo8ieJPHGlkBsOfmreSxijTod\n" +
            "Zz9MXsgcx7b//u0uQryViJoZHWbtnXOFjjNcGWBtS084NKWl9w==\n" +
            "=yPPE\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    public static final String ROMEO_UID = "xmpp:romeo@montague.lit";
    public static final long ROMEO_KEY_ID = 334147643349279223L;
    public static final String ROMEO_FINGERPRINT_STRING = "35D299D08A2F7D80230B095D04A32182E05E21F7";
    public static final OpenPgpV4Fingerprint ROMEO_FINGERPRINT = new OpenPgpV4Fingerprint(ROMEO_FINGERPRINT_STRING);

    /**
     * Public key of xmpp:romeo@montague.lit.
     */
    public static final String ROMEO_PUB = "" +
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "mQENBFrxopkBCADiYg/+mEObXgxuMW6/LFKpEyaJK9pBMgutuxnYZ9PXWZmOhDIT\n" +
            "Ugm9X9YJ3Qh94KaHge9F4uCeFASmM1vvUTRFTEb1W5RR9ZE/sy/cdAttnZ5JloPi\n" +
            "CT3HDMIJAxIXhRJkeUR9GUb51ql27bMXl6lFh865VdNSXN/B8FzRQHENxv1Bq/6Z\n" +
            "iQOViIETeRRgO+u6u2iZkYlHgYMaoMK7+YiNlHXanU9Atcuaz0ZCJS/XFNH89iqB\n" +
            "Kvnv7KCQh4FhrNMLJRzNPXV8MY05nn0zF72qeEsniB16Xde18lMro8fQehg2mLwc\n" +
            "XGtCwCKI6QbZVxYQt77r3ZACiwl66soFWijVABEBAAG0F3htcHA6cm9tZW9AbW9u\n" +
            "dGFndWUubGl0iQFOBBMBCAA4FiEENdKZ0IovfYAjCwldBKMhguBeIfcFAlrxopkC\n" +
            "Gy8FCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQBKMhguBeIfcj8AgAu1wubUwr\n" +
            "2aQmDN3OqRM4M4yRL3oyYMkCKIjqD6KEeFsIXSSkXOuREJKEo8Mb1+ewV0SYmHCC\n" +
            "K3bKKq3m71AQ7evDhKGshacPYesiDvMdHWQdQnjfaoHhyn9qIKl7H0Xv1yf/wyuG\n" +
            "ANy1jYgtCEuYw7D+EsqNDdn8Xh+k/9s4aMI/6mfC0yGZgG8EyLTfbZkGPoS4aZfV\n" +
            "AGFbuqryg48dXtnuzAPKcdgMTTMSnmR729YlfkjCffcFaldyXoe1VMbudUO7nkO9\n" +
            "g65i5EXenkbc2h0TRDQ4lDFQyModqFTwYFYxAf/RA6tuhIQEoCnpCytFMvrRKMb3\n" +
            "Bx5vYRDVmE3jeg==\n" +
            "=2jSg\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    /**
     * Private key of xmpp:romeo@montague.lit.
     */
    public static final String ROMEO_SEC = "" +
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "lQOYBFrxopkBCADiYg/+mEObXgxuMW6/LFKpEyaJK9pBMgutuxnYZ9PXWZmOhDIT\n" +
            "Ugm9X9YJ3Qh94KaHge9F4uCeFASmM1vvUTRFTEb1W5RR9ZE/sy/cdAttnZ5JloPi\n" +
            "CT3HDMIJAxIXhRJkeUR9GUb51ql27bMXl6lFh865VdNSXN/B8FzRQHENxv1Bq/6Z\n" +
            "iQOViIETeRRgO+u6u2iZkYlHgYMaoMK7+YiNlHXanU9Atcuaz0ZCJS/XFNH89iqB\n" +
            "Kvnv7KCQh4FhrNMLJRzNPXV8MY05nn0zF72qeEsniB16Xde18lMro8fQehg2mLwc\n" +
            "XGtCwCKI6QbZVxYQt77r3ZACiwl66soFWijVABEBAAEAB/4mu5p69/hRQ+UikWie\n" +
            "Yun9rZ4hSBR+pR5kaifA4/rV1Km2PZ4HujiaYyRO6beDOgWkF7IlpezCfzBQc2ce\n" +
            "ailkVemqHzIgV8CzQmhE8sHlzlr/wjXsXaJpRSCJxDG7PnRoJmt2b/W512WFSKQk\n" +
            "vDklAVh4U1vlsqhCGWr4DmuJbJkRyDhcX01tplRwim283F7bGqRcMBmKMZHiMgVc\n" +
            "0u84EYKKVizJ3YAaaVqZyHb4qdeKK2ak3fPNuGT/oGd2sxnkL+BZGjJpu3RGpTA1\n" +
            "tbOvOQnJGHQtABFxE8n6H9dHPJGtgyz2+udjUhL/P/E3PDoXazZkXRq2oHZKgg0f\n" +
            "AwOBBADsWncHgvz15rXPF7O6AivbGTJ5ctkgVy4U3Fu2sk9rf0fx0sryBSqtTBw1\n" +
            "Uvn/p9RwTsKw6fng6Nf78xpZFlUDB00YCcuWkGodxvjTAyB0dtBmkhopeKi0dmHh\n" +
            "ndnR6Pv0CsXu8nG7lUi+q6s3oc4h2OfDBhrqsyYY5M2gGit3dQQA9TNuinJD9XXv\n" +
            "QRyauMnSJ5xRcfOu8QCxZlllCvffZjSGCPoVjUpJEe9qsVbXVj2GYCxjLCSXV0V+\n" +
            "vlJfdPrl1BhZ3fmEpg0u7SyGDDOe8fe1ehk5sAeL8O0eFWlPSEaEccsjlpJ2FO0n\n" +
            "P04SZdOeM6wmhDTEDzpFnjbPndQTH+ED/R1zNzr55DvxQodmrW/BvTmhGQ22rHtk\n" +
            "IUfbeMaVfUvNLJA/JksrUIx3Gga9QCDZgfm1RsRhLUlHiqTQe23sPWgKOsbf5O1j\n" +
            "XJZaCNZ7LloVQbkG7xFcnb/n1+JjBr4FxXjAA6cY/iRGlznjIIaasyklKm1/4LuQ\n" +
            "hnH3QqTvCN3dOFS0F3htcHA6cm9tZW9AbW9udGFndWUubGl0iQFOBBMBCAA4FiEE\n" +
            "NdKZ0IovfYAjCwldBKMhguBeIfcFAlrxopkCGy8FCwkIBwIGFQoJCAsCBBYCAwEC\n" +
            "HgECF4AACgkQBKMhguBeIfcj8AgAu1wubUwr2aQmDN3OqRM4M4yRL3oyYMkCKIjq\n" +
            "D6KEeFsIXSSkXOuREJKEo8Mb1+ewV0SYmHCCK3bKKq3m71AQ7evDhKGshacPYesi\n" +
            "DvMdHWQdQnjfaoHhyn9qIKl7H0Xv1yf/wyuGANy1jYgtCEuYw7D+EsqNDdn8Xh+k\n" +
            "/9s4aMI/6mfC0yGZgG8EyLTfbZkGPoS4aZfVAGFbuqryg48dXtnuzAPKcdgMTTMS\n" +
            "nmR729YlfkjCffcFaldyXoe1VMbudUO7nkO9g65i5EXenkbc2h0TRDQ4lDFQyMod\n" +
            "qFTwYFYxAf/RA6tuhIQEoCnpCytFMvrRKMb3Bx5vYRDVmE3jeg==\n" +
            "=LZ1b\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    public static final String EMIL_UID = "<emil@email.user>";
    public static final long EMIL_KEY_ID = 6284463849526474508L;
    public static final String EMIL_FINGERPRINT_STRING = "4F665C4DC2C4660BC6425E415736E6931ACF370C";
    public static final OpenPgpV4Fingerprint EMIL_FINGERPRINT = new OpenPgpV4Fingerprint(EMIL_FINGERPRINT_STRING);
    public static final Date EMIL_CREATION_DATE = new Date(1578852104000L);

    /**
     * Public key of <pre><emil@email.user></pre>.
     */
    public static final String EMIL_PUB = "" +
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: BCPG v1.64\n" +
            "\n" +
            "mFIEXhtfCBMIKoZIzj0DAQcCAwTGSFMBUOSLusXS8hdNHbdK3gN8hS7jd4ky7Czl\n" +
            "mSti+oVyRJUwQAFZJ1NMsg1H8flSJP1/9YbHd9FBU4bHKGKPtBE8ZW1pbEBlbWFp\n" +
            "bC51c2VyPoh1BBMTCgAdBQJeG18IAhsjBRYCAwEABAsJCAcFFQoJCAsCHgEACgkQ\n" +
            "VzbmkxrPNwz8rAD/S/VCQc5NJLArgTDkgrt3Q573HiYfrIQo1uk3dwV15WIBAMiq\n" +
            "oDmRMb8jzOBv6FGW4P5WAubPdnAvDD7XmArD+TSeuFYEXhtfCBIIKoZIzj0DAQcC\n" +
            "AwTgWDWmHJLQUQ35Qg/rINmUhkUhj1E4O5t6Y2PipbqlGfDufLmIKnX40BoJPS4G\n" +
            "HW7U0QXfwSaTXa1BAaNsMUomAwEIB4h1BBgTCgAdBQJeG18IAhsMBRYCAwEABAsJ\n" +
            "CAcFFQoJCAsCHgEACgkQVzbmkxrPNwxOcwEA19Fnhw7XwpQoT61Fqg54vroAwTZ3\n" +
            "T5A+LOdevAtzNOUA/RWeKfOGk6D+vKYRNpMJyqsHi/vBeKwXoeN0n6HuExVF\n" +
            "=a1W7\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    /**
     * Secret key of <pre><emil@email.user></pre>.
     */
    public static final String EMIL_SEC = "" +
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: BCPG v1.64\n" +
            "\n" +
            "lHcEXhtfCBMIKoZIzj0DAQcCAwTGSFMBUOSLusXS8hdNHbdK3gN8hS7jd4ky7Czl\n" +
            "mSti+oVyRJUwQAFZJ1NMsg1H8flSJP1/9YbHd9FBU4bHKGKPAAD5AdecgJ92sAXP\n" +
            "l4U4oW6l4KKUb8IT3J5g68Z+Q9WIq6kS5bQRPGVtaWxAZW1haWwudXNlcj6IdQQT\n" +
            "EwoAHQUCXhtfCAIbIwUWAgMBAAQLCQgHBRUKCQgLAh4BAAoJEFc25pMazzcM/KwA\n" +
            "/0v1QkHOTSSwK4Ew5IK7d0Oe9x4mH6yEKNbpN3cFdeViAQDIqqA5kTG/I8zgb+hR\n" +
            "luD+VgLmz3ZwLww+15gKw/k0npx7BF4bXwgSCCqGSM49AwEHAgME4Fg1phyS0FEN\n" +
            "+UIP6yDZlIZFIY9RODubemNj4qW6pRnw7ny5iCp1+NAaCT0uBh1u1NEF38Emk12t\n" +
            "QQGjbDFKJgMBCAcAAQCMHcK/wrUR1R8HKvLUFzUB/a5zj1reOzQOsFtoLte3Mg6u\n" +
            "iHUEGBMKAB0FAl4bXwgCGwwFFgIDAQAECwkIBwUVCgkICwIeAQAKCRBXNuaTGs83\n" +
            "DE5zAQDX0WeHDtfClChPrUWqDni+ugDBNndPkD4s5168C3M05QD9FZ4p84aToP68\n" +
            "phE2kwnKqweL+8F4rBeh43Sfoe4TFUU=\n" +
            "=Pqd/\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    public static final String CRYPTIE_UID = "cryptie@encrypted.key";
    public static final String CRYPTIE_PASSWORD = "password123";
    public static final Passphrase CRYPTIE_PASSPHRASE = Passphrase.fromPassword(CRYPTIE_PASSWORD);
    public static final long CRYPTIE_KEY_ID = -821156605394703576L;
    public static final String CRYPTIE_FINGERPRINT_STRING = "A395D3BA58CA3FA0DE8F2991F49AAA6B067BAB28";
    public static final OpenPgpV4Fingerprint CRYPTIE_FINGERPRINT = new OpenPgpV4Fingerprint(CRYPTIE_FINGERPRINT_STRING);

    /**
     * Public EC key of cryptie@encrypted.key.
     */
    public static final String CRYPTIE_PUB = "" +
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: BCPG v1.64\n" +
            "\n" +
            "mFIEXht1HBMIKoZIzj0DAQcCAwQgSQNsoRMqlb9bm4XmXRxIyJoXhIADAQcqkrkt\n" +
            "uWvGWeu5m5HLi1LfwVHZWTGff94uq/uK3O3Vg0W4EQjF8qB6tBVjcnlwdGllQGVu\n" +
            "Y3J5cHRlZC5rZXmIdQQTEwoAHQUCXht1HAIbIwUWAgMBAAQLCQgHBRUKCQgLAh4B\n" +
            "AAoJEPSaqmsGe6soOWEBAMPW0d/DBVIs9tscIt+jXbg49kwYo57rbbEmp/X05RZS\n" +
            "AQDHDMOkesBjv9zQToWGGb0FmkWbrDCzA0i10mbyNAe4d7hWBF4bdR0SCCqGSM49\n" +
            "AwEHAgMENs+3TanqesZgSXn3gtz3QEqu8ZLID2+8U1Jh2KkkiasI1S+48k+CMiFb\n" +
            "0CclBy6+mX0k8chzj8wCNOgM74DB0AMBCAeIdQQYEwoAHQUCXht1HQIbDAUWAgMB\n" +
            "AAQLCQgHBRUKCQgLAh4BAAoJEPSaqmsGe6sovOUA/3Zb9qJM/9znjFM9hxMVL0y3\n" +
            "9wKEqKkSPRj0WVr6O5ybAP9S/Q/tzQ2in19xBg06XzNyd5a1nrwR9n4kjd4VpQWh\n" +
            "xQ==\n" +
            "=6SyK\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    /**
     * Encrypted secret EC key of cryptie@encrypted.key.
     *
     * Password: {@link #CRYPTIE_PASSWORD}
     */
    public static final String CRYPTIE_SEC = "" +
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: BCPG v1.64\n" +
            "\n" +
            "lKUEXht1HBMIKoZIzj0DAQcCAwQgSQNsoRMqlb9bm4XmXRxIyJoXhIADAQcqkrkt\n" +
            "uWvGWeu5m5HLi1LfwVHZWTGff94uq/uK3O3Vg0W4EQjF8qB6/gkDApZ4y1XLA8XH\n" +
            "YM7ke2XPiiBQfapmHmZD0OUvlsTwSwDeg7wM9caWduXp7GU5j00T0gzr04xE83bw\n" +
            "pjjMxa1YRaOAJcjm1W/GGXRfXA/vSAO0FWNyeXB0aWVAZW5jcnlwdGVkLmtleYh1\n" +
            "BBMTCgAdBQJeG3UcAhsjBRYCAwEABAsJCAcFFQoJCAsCHgEACgkQ9JqqawZ7qyg5\n" +
            "YQEAw9bR38MFUiz22xwi36NduDj2TBijnuttsSan9fTlFlIBAMcMw6R6wGO/3NBO\n" +
            "hYYZvQWaRZusMLMDSLXSZvI0B7h3nKkEXht1HRIIKoZIzj0DAQcCAwQ2z7dNqep6\n" +
            "xmBJefeC3PdASq7xksgPb7xTUmHYqSSJqwjVL7jyT4IyIVvQJyUHLr6ZfSTxyHOP\n" +
            "zAI06AzvgMHQAwEIB/4JAwKWeMtVywPFx2Ci0C0EtcGVxy847rppLWNcaR3FnP/9\n" +
            "MGxLKDvLdGljC829gxxf5wq/5qUehPqFnQD11L00cFScvlVzs53nO34iUVsJl079\n" +
            "iHUEGBMKAB0FAl4bdR0CGwwFFgIDAQAECwkIBwUVCgkICwIeAQAKCRD0mqprBnur\n" +
            "KLzlAP92W/aiTP/c54xTPYcTFS9Mt/cChKipEj0Y9Fla+jucmwD/Uv0P7c0Nop9f\n" +
            "cQYNOl8zcneWtZ68EfZ+JI3eFaUFocU=\n" +
            "=1d67\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    public static PGPSecretKeyRing getJulietSecretKeyRing() throws IOException, PGPException {
        if (julietSecretKeyRing == null) {
            julietSecretKeyRing = new PGPSecretKeyRing(
                    PGPUtil.getDecoderStream(new ByteArrayInputStream(JULIET_SEC.getBytes())), calc);
        }
        return julietSecretKeyRing;
    }

    public static PGPSecretKeyRingCollection getJulietSecretKeyRingCollection() throws IOException, PGPException {
        if (julietSecretKeyRingCollection == null) {
            julietSecretKeyRingCollection = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(new ByteArrayInputStream(JULIET_SEC.getBytes())), calc);
        }
        return julietSecretKeyRingCollection;
    }

    public static PGPPublicKeyRing getJulietPublicKeyRing() throws IOException {
        if (julietPublicKeyRing == null) {
            julietPublicKeyRing = new PGPPublicKeyRing(
                    PGPUtil.getDecoderStream(new ByteArrayInputStream(JULIET_PUB.getBytes())), calc);
        }
        return julietPublicKeyRing;
    }

    public static PGPPublicKeyRingCollection getJulietPublicKeyRingCollection() throws IOException, PGPException {
        if (julietPublicKeyRingCollection == null) {
            julietPublicKeyRingCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(new ByteArrayInputStream(JULIET_PUB.getBytes())), calc);
        }
        return julietPublicKeyRingCollection;
    }

    public static PGPSecretKeyRing getRomeoSecretKeyRing() throws IOException, PGPException {
        if (romeoSecretKeyRing == null) {
            romeoSecretKeyRing = new PGPSecretKeyRing(
                    PGPUtil.getDecoderStream(new ByteArrayInputStream(ROMEO_SEC.getBytes())), calc);
        }
        return romeoSecretKeyRing;
    }

    public static PGPSecretKeyRingCollection getRomeoSecretKeyRingCollection() throws IOException, PGPException {
        if (romeoSecretKeyRingCollection == null) {
            romeoSecretKeyRingCollection = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(new ByteArrayInputStream(ROMEO_SEC.getBytes())), calc);
        }
        return romeoSecretKeyRingCollection;
    }

    public static PGPPublicKeyRing getRomeoPublicKeyRing() throws IOException {
        if (romeoPublicKeyRing == null) {
            romeoPublicKeyRing = new PGPPublicKeyRing(
                    PGPUtil.getDecoderStream(new ByteArrayInputStream(ROMEO_PUB.getBytes())), calc);
        }
        return romeoPublicKeyRing;
    }

    public static PGPPublicKeyRingCollection getRomeoPublicKeyRingCollection() throws IOException, PGPException {
        if (romeoPublicKeyRingCollection == null) {
            romeoPublicKeyRingCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(new ByteArrayInputStream(ROMEO_PUB.getBytes())), calc);
        }
        return romeoPublicKeyRingCollection;
    }

    public static PGPSecretKeyRing getEmilSecretKeyRing() throws IOException, PGPException {
        if (emilSecretKeyRing == null) {
            emilSecretKeyRing = new PGPSecretKeyRing(
                    PGPUtil.getDecoderStream(new ByteArrayInputStream(EMIL_SEC.getBytes())), calc);
        }
        return emilSecretKeyRing;
    }

    public static PGPSecretKeyRingCollection getEmilSecretKeyRingCollection() throws IOException, PGPException {
        if (emilSecretKeyRingCollection == null) {
            emilSecretKeyRingCollection = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(new ByteArrayInputStream(EMIL_SEC.getBytes())), calc);
        }
        return emilSecretKeyRingCollection;
    }

    public static PGPPublicKeyRing getEmilPublicKeyRing() throws IOException {
        if (emilPublicKeyRing == null) {
            emilPublicKeyRing = new PGPPublicKeyRing(
                    PGPUtil.getDecoderStream(new ByteArrayInputStream(EMIL_PUB.getBytes())), calc);
        }
        return emilPublicKeyRing;
    }

    public static PGPPublicKeyRingCollection getEmilPublicKeyRingCollection() throws IOException, PGPException {
        if (emilPublicKeyRingCollection == null) {
            emilPublicKeyRingCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(new ByteArrayInputStream(EMIL_PUB.getBytes())), calc);
        }
        return emilPublicKeyRingCollection;
    }

    public static PGPSecretKeyRing getCryptieSecretKeyRing() throws IOException, PGPException {
        if (cryptieSecretKeyRing == null) {
            cryptieSecretKeyRing = new PGPSecretKeyRing(
                    PGPUtil.getDecoderStream(new ByteArrayInputStream(CRYPTIE_SEC.getBytes())), calc);
        }
        return cryptieSecretKeyRing;
    }

    public static PGPSecretKeyRingCollection getCryptieSecretKeyRingCollection() throws IOException, PGPException {
        if (cryptieSecretKeyRingCollection == null) {
            cryptieSecretKeyRingCollection = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(new ByteArrayInputStream(CRYPTIE_SEC.getBytes())), calc);
        }
        return cryptieSecretKeyRingCollection;
    }

    public static PGPPublicKeyRing getCryptiePublicKeyRing() throws IOException {
        if (cryptiePublicKeyRing == null) {
            cryptiePublicKeyRing = new PGPPublicKeyRing(
                    PGPUtil.getDecoderStream(new ByteArrayInputStream(CRYPTIE_PUB.getBytes())), calc);
        }
        return cryptiePublicKeyRing;
    }

    public static PGPPublicKeyRingCollection getCryptiePublicKeyRingCollection() throws IOException, PGPException {
        if (cryptiePublicKeyRingCollection == null) {
            cryptiePublicKeyRingCollection = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(new ByteArrayInputStream(CRYPTIE_PUB.getBytes())), calc);
        }
        return cryptiePublicKeyRingCollection;
    }

    public static final String TEST_MESSAGE_01_PLAIN = "This message is encrypted\n";

    /**
     * Test Message signed with {@link #JULIET_SEC} and encrypted for {@link #JULIET_PUB}.
     */
    public static final String MSG_SIGN_CRYPT_JULIET_JULIET =
            "-----BEGIN PGP MESSAGE-----\n" +
                    "\n" +
                    "hQEMA7S1CctZNuA+AQf/SMX7NTOaAynogTVKE9BMWSj5fgK+7sFrCKiLYbungJEu\n" +
                    "RA/fYqaJNfZN3GARqsHcGaGihQDXr0thnx71+37NhV2cHVeFkeMsHmJf/74lRrHk\n" +
                    "QBXDv2ez0LxUwhkE15/d/NTlT/fm8Vzce6rsm7/ZvzQIaWYyDCnpHXyftJplKd+Y\n" +
                    "PW0PaoFRq1wlZKcNUp/1a3xxpbSpvsYkiAxpdGIwvgUIb85KpFN0EWD3aH8C65it\n" +
                    "Iphuv8CEaKqcO0hchQr7kYclEM0qcmm1ukw8+niTV8TFqAzNZh7DF/IWaMeamgfA\n" +
                    "P6pAB1oy7YoWUPQgy7mczD76WzPgJjy8y0hxFd9/f9LA2gEZZ/ClAiX0gHglc4oa\n" +
                    "j5iKIICvtTQzKYL29mW66BUistqMavz6eqHRggoADCBzfgOwuoAQxZMyj33bmrWm\n" +
                    "831LMu+4sZyx6ihLvZ0YcDKMd7C7pQJ3Ucxt+DJUlTmo6KxzGdwGhq7cUcXwCuer\n" +
                    "3MoPIV5YQwXBMbYN9fXV+yQagquz0z7r5igE7AQ1d9SyLJoQ3IHXnsa0xcUVZrIs\n" +
                    "A59LdIXEeRk/Ctjqp34UdTsuUPzervPexY+kNQVSQ2VODhwM5IowzPZFGviPNJYa\n" +
                    "nGt27c4rsQ3sSC/WkdUxdaVY2+m7JktfnklUyVyC5wE1Nw+bO3sni6FeoP/fVSVi\n" +
                    "HmPy7vMj23cQcvcAnuUEd4Qua0lwVrN1MTUggfZOzcH4+9rgMn/uYRAwPH9hdLWQ\n" +
                    "vziQMH5qtJMyWy08m9hIxleoI3+zIGSbra15R+hdWwEaD9+Pak//0Q0thFMeNww7\n" +
                    "Y8gK8CSbUHbUjefUIx0s+JjrDGtXG8xfl63MLBbU7yLLB4Vcx77Sxxi3yt5DTi0n\n" +
                    "GmPGRU4LsOYbpPFy\n" +
                    "=caif\n" +
                    "-----END PGP MESSAGE-----";

}
