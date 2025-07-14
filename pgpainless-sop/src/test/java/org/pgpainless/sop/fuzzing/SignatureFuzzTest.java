// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop.fuzzing;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.pgpainless.sop.SOPImpl;
import sop.SOP;
import sop.Verification;
import sop.exception.SOPGPException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class SignatureFuzzTest {

    private final SOP sop = new SOPImpl();
    private final byte[] data = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);

    private final String v4_ed25519 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: D7BC FF6B B105 40D9 87F9  CB6E 542D C9F6 FCAE AD63\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "mDMEaGzu+BYJKwYBBAHaRw8BAQdAlqjB241N44drAJvxa3wx0uRb5bxuVNXrCwPZ\n" +
            "yf4Qg+O0HEFsaWNlIDxhbGljZUBwZ3BhaW5sZXNzLm9yZz7ClQQTFgoARwWCaGzu\n" +
            "+AkQVC3J9vyurWMWIQTXvP9rsQVA2Yf5y25ULcn2/K6tYwKeAQKbAQUWAgMBAAQL\n" +
            "CQgHBRUKCQgLBYkJZgF/ApkBAADVIwEAi599IgoqQbvetYicOt9XobSQKH+4/tB/\n" +
            "cmHgD7HkGu8A/jYoA0CaYuYNWw8ZYQ8QCUIAkXApm8fO9iyTx0QU1kQMuDMEaGzu\n" +
            "+BYJKwYBBAHaRw8BAQdA48KEYPTPnV86ycWzAk82aHPF2Fke5cLFsQn7/laFT1DC\n" +
            "wBUEGBYKAH0Fgmhs7vgCngECmwIFFgIDAQAECwkIBwUVCgkIC18gBBkWCgAGBYJo\n" +
            "bO74AAoJECL1fW9vQUTUldQBALcsF4e23VatOfew9CXwEiL6P5LMh7E8n/yUVR+j\n" +
            "NBr9AP0bxSZ1UbdRIrWpg/Itpl9h98gtpT9rdVs02n0+xs5GDAAKCRBULcn2/K6t\n" +
            "Y4UQAQCG/xpMgjpVNNs3wzHeVB0OCRKXsWkqHQr6xnEDAObdpwD7BD10DpdQDnSa\n" +
            "HP7CArFQIuA78aIXpaVidfWVMu1mEAm4OARobO74EgorBgEEAZdVAQUBAQdAXgno\n" +
            "M3Qa9wevqtyAY5MzVz3y6KTYtnfrC/YXG1fc7Q4DAQgHwnUEGBYKAB0Fgmhs7vgC\n" +
            "ngECmwwFFgIDAQAECwkIBwUVCgkICwAKCRBULcn2/K6tY7GuAP9Kf1Ec1GJmZ99U\n" +
            "HsgiN60os+6adMLj4G2ASiIbNSDvKgD9F/VLFIb/eN7kJQp3E5C15x5pMMKEI/rj\n" +
            "wdrKmYH3aAw=\n" +
            "=4uX6\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";
    private static final String v4_rsa4096 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: C2C1 DB5E 3AE2 9711 62D9  7BFB 101D 531D 1C69 12A7\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "xsFNBGhtEaoBEACrLPrTPIE2pmjojrYJEDHkRLVqGE1RQ5DOvaaQTYv/IkLPeqGM\n" +
            "NQUHBowKXZQ5mnJn66qztSdape0j+7QPRlt1XFeNHmsPl2lJ+2IUrWnf3XIN+SIo\n" +
            "JE45Rt8u1hOyokDbwC+MAM0dcC8GiuN+TUlXbpdqgV3MREpHNuWu4u+19lT4/RYl\n" +
            "AxJt5/NyGqW+0MoSSN4ioUhbZdqqgugW95VJfBkMiTX+6/wPw/tpfHIulwbak1B0\n" +
            "PAGGQZpU1+6j+RUbACukW3nAM9rMuHdlms1QWk8IiRZogid9msEHYF1GiOcHoGH9\n" +
            "N4uF5q+7XsosAeBi0P8ogdlg9TDMZJEw+GuL2XCEZD2qaiYXp0M712SS8qgpKWGw\n" +
            "g9kqjCGAH8WmU+txhecWyyNA6fYllQzOn3os32bw0DV1sP9EmAR+xsW4r58rR7+q\n" +
            "e9UH2G8ISfF16asSwl9vyLeOteG9WbZS6VLRy05nKnD8hkbphsVXxpLf5vtIB/DH\n" +
            "qKb59W3azKzVI67vzeTmQqsP/aqIbcDZcpVRDxbx80zqZzHlfAwtb1mIVaSfJlm4\n" +
            "ASmh1K+KWVqmYLn10iUwNub9DQ5NUBkYIdEt2u9FXai5ZB08mdxQDR/fsNHLc5SJ\n" +
            "r16AcISKonFPewaCpDoxb76LkyrLGF/kudxZbOj5k9E3MqRk3FAqNah7XwARAQAB\n" +
            "zRxBbGljZSA8YWxpY2VAcGdwYWlubGVzcy5vcmc+wsGdBBMBCgBRBYJobRGsCRAQ\n" +
            "HVMdHGkSpxahBMLB21464pcRYtl7+xAdUx0caRKnApsBBRUKCQgLBRYCAwEABAsJ\n" +
            "CAcJJwkBCQIJAwgBAp4JBYkJZgGAApkBAABfBw//QmBNjhqq7f5NIsv+WQIPhZh+\n" +
            "fI0eogQnK45Ni64n1teXOLg8YnaHBFMQNpJcgCWK0zgem7TKk2nDNchWHohrvJMX\n" +
            "WrSSkjWE+r24iFCiEuXt69rfbu/Ya5bHXdy4cmGgjmbkLuLZwqLZ4hm+IWA5ndF8\n" +
            "l2hL2kDl9LXlgiDt0V85+t7VBHRF4S5MoTyj4osuczKL2O7tBw0vDRdEQIicOcYD\n" +
            "UTADVDpqJpeCb0qhIsG9Hcf6XeXpzWLZyNe32isXM19GxCP1w+jtto6jEuJXvotu\n" +
            "F3Yt8h6P24iLKnAGr8EhwWG6w4oTYpKkkcbn82NfGZqFZV74mh3pE8fKAFBGPa4q\n" +
            "q2iftW8be+QPTZcTA5g0ZSWECGGzKqia6+q6tjThn6MSzWpB3Orb3Kr4v6GQ6GUE\n" +
            "NVw0NACU/WrIMKJJzarlxgcndPgg/xUHF7btEifgfhtf5t/dVUG16p0x+bqu5GFZ\n" +
            "e9fskH6Km5eNsTvBVFWRKzaPqJFlf27VB4nPHNhl3SuiIAZ3nq23jyfTjAByH7nQ\n" +
            "URYRRlucC2+XPOj3YRs6JLfjppPLQX4txIuzFV1gTwRFofzH+c9i6rUYCNXGnBWA\n" +
            "WO0mKcCZ63X+tmeeo0aAcPP+4Ze1kh7rNIYMp8p9wNneGfNjBn/qniU3b7XHrKrg\n" +
            "N3ljkagsOKpZdSzd+KPOwU0EaG0RrAEQAOa9Ak2nUI0cGRSoBedM0yDRkUbCrGSN\n" +
            "TuepnVrnIDzr1JNc1avad9Zn2Hj7YV1CjHPKvVdI8jmQ/g6T+ceKUnB5qXq7n7Wb\n" +
            "HQTvlNaz7/T/Om4GOXprWa5XZdRoj8BrI0nId/KCK14VZUO7VHVkBh+RojtJwpZi\n" +
            "3m8Y7ODU9MuNgrF6LDvViCHW80uMkW3hlZdTLKQmkYKDMEpS3z+ynd3UYzu6Orwk\n" +
            "ir8OFcamk0sapTh+vNDTjdxji1zD47Nq6H6QaSX5tRuz+gwxkoPkeShemBU+E1Hw\n" +
            "N5rNLvVmD/hZwMqg95m2GghHLAol2NKvwfPFGyHXSZ/H0iyhyfmhPwd0keg/oV0k\n" +
            "CFaPbdE8FePefgFl4A5Njxkdp8Mqxm9ONPLjK2kWwGYCQBZi9R8N6O/310IwCJqc\n" +
            "jBht87MychHyTImgdF3MlSQiWbWTzgeBq12353n7ZsfCI8IrX4hmW/7uvwDynusU\n" +
            "bC+CZTQG46O4xYhYNmg7livBeTq0ljChMKcwob/H8a0SrYFOL/85QK6ZsIh38R0B\n" +
            "nHR4Mx9wE92jj+fFmbqUCXDUhu1KwnhgfCZLqD90qoRemws5Fqelgr+pkVgD2haI\n" +
            "V2PL4O5uEJ6wgp7uQUliR5v7zwH/7MYBlJgLdlV4Jpz9d3MUfYoFUMZA1CjFIjz9\n" +
            "TDpZ2tjJmITtABEBAAHCw5UEGAEKAkkFgmhtEa0JEK0galCgMdvCFqEEdEBU9q1n\n" +
            "gJHTPZc3rSBqUKAx28ICmwLBXSAEGQEKAAYFgmhtEa0ACgkQrSBqUKAx28KFpg//\n" +
            "X2qYs9ZACD/7hw7Oj+AANkgTm7Jon2EYMwcRfTq5ZKuZ6FGaY6x8pZMRR3tmsTjV\n" +
            "U8dWPmb3mgF2dn7iNoAn/vNLEl7iKy+Dj053gu29+6vGcMbCxQT8RhDFsWhYJR86\n" +
            "yfW4ze3b0hv5bwchpueq+s/vqTmqhsjsTDTCzbx46Hrj643xOIlckKnrPMcErnE1\n" +
            "0ZgL5J9pjfyZ1dZjip30LRspyXHSE0h2AAvHKjAggraM+SmdtGHu3SCefXTtAlLl\n" +
            "hE2u0ifoQAb4iQX2Ca5EjP6Qvjxk8Zez6M6Rg4v6YDhm+S7j+086bgF5gTmb9RTM\n" +
            "K352kjTR8t8EYk8Mm02oTVa0dEOtP0L9mfIbBM9VH5YGxEiQhjDsh5/dQYo0tJwn\n" +
            "Ipf0edeqYk2ESS70yhgX2zbSBNS7AmxTHWI0x0n7UnSLsFHO6pX2PeAfL65XkTcK\n" +
            "n59wptC/wDV2IFomtNFfNTX3k5XsxWDer+eF1liyZF4EwaUc0cVWCPVY07xuL6EJ\n" +
            "bCJ8euhv5zslo1bmfm+EGHnVWelPurR1OWp+tqjUTZX05+w+dcIzIwYo0xHkbJV0\n" +
            "3HvcEuEyxl9EN/+WovXqdUMdHiXPXL7JslOXVA30T1EQ/q8ubeL+6E9TmiVsHTsv\n" +
            "nhsqFtkLsp2JveQuoPiYmI/+s/lPcGVGXWIRZhzgcWgAABuSD/9kREGB2W4MsXq9\n" +
            "0shRP7ae0KjWbORVPSwJMQcORYIDAizNk882O9mccJfpdpLKXeib8Am5FoUdqsES\n" +
            "5sZbb65hOr9vToLenICZ7Fm8Ojqk1W4U2XiF3aGGmalqK17ebfYqQXMTLqawcvQn\n" +
            "G1amJ4x3qmV6NUMRVynhzZWqV53oZ0M+jVaBZkSG0MPTYMaDfpB9TSkbiCyg40OE\n" +
            "PxVBrlHuQOf/hwfWH09V06WvY7/ATa9Ofy1VqIJif/UJgCAT7hxPqCYeMtID5Nm5\n" +
            "sREn3Qq+jizZ770CwjnDu4xKcDasjoJkiFf648GmYCCbgXDcL+lbm52m9XDVb34L\n" +
            "PUMr8u2BSyXMODNIW+lPBhsbAwp0iq3MuQUa00zmnebmilqhV8wV6surzy29ABbJ\n" +
            "2z+JJh/DmqEiW+5AimxbhfbORKV6Bw3A60A53osz5tnx5H0odEA4Wy669yV0lqW0\n" +
            "bi/Jx8FCpoI+0yvd5DEjQwRyJhdzuW1R5kMc2mM92jN+IjtA9vAqqJwl6X+TL7yT\n" +
            "rB8u6SXGfRS3Uss7WaTiQJ3SmXCOwL4i5M7ME7mRHLwuw2iYQZETfUg/Gu6YlAlT\n" +
            "MDhWt96BR28TG+Ijpls+DUF+CcBGXLBlaRSH3/jpycRmaqgXrfqh9CxWCG66LBIZ\n" +
            "QkqC79Zn0Zonu1DGGU4rrdc4Na4Kgs7BTQRobRGtARAAvsYZoHkaH7hSJTqgy199\n" +
            "Q3NJRp2PiqlG48LpHdSUF79fOvwQv0VBZ+ILG+h+Q2VxzLvn/cKpqZrsbBAa0QPQ\n" +
            "pnfxtrn7W+jg9Ba+Pp36ugnc2Jc8NMO265AZh4OEn8Sqaj1kJSu01Ft2oT/1v0BZ\n" +
            "p/W4kXas/RQHu6s9zHDN4l8ndrxZbmExAEn/2yLX4lMQQZsBGt8Mc23JFFLF8gek\n" +
            "dmnjOyMuWuYslZ3P/74nofxHLdNfXhyIeuLP8RuAsP6ScA0F38CZt1kuD2CAf35B\n" +
            "cLhm4noRaWYLi6WcQ80H1DlDIb8w0bzwZoZob1E2hHiT8UEYbLtYb5ASkdoCxz/p\n" +
            "//LBCon4sarthEmyvGiHswpDnw1LRBIsIUYOoNYb/IajRjPfztQ0wiY7r6wmAKo9\n" +
            "bRB/QZv/K9v6/NEWEVw5w5drAPyFwl4fkdp5QqtbGseUI25dj+JTruIU0xmtl6mL\n" +
            "teN4tY2Php++lFTN0rFdHa4TlKBwjUBJgiNQ+YAwBrivDd7a3tTdPbcq8et3ahw4\n" +
            "5gc0koGLco/mCGUgIqt8MPLG0nV5YhFYztPcHrXSjvoQCG25sevEeOHMq5NZw4JJ\n" +
            "uhv0iz/cxdZcCZWIauuMvblDehDP2RVqlozkB7wG4+G0mGJxmPgltufKsnyycZgc\n" +
            "xLCdKH1BoVG9Ght/PuJsRdEAEQEAAcLBdgQYAQoAKgWCaG0RtwkQq5KiltUsy68W\n" +
            "oQTuGgCTnm/OWBS9N6OrkqKW1SzLrwKbDAAApw0P/3/5H5MOcFrrSOs5lC4DsBdJ\n" +
            "H4JPgkS/IqqyMqfVuVzHXER7RXrO8W5K3tIY+uWxLx9nG2v79KA4djlPGKdMvQ1b\n" +
            "fXAlSZFE3vHcV7VmvqoH46Ogz3z2hFaJdvImO7qZOq2qmMTPXsaK6zTwehEGNGF7\n" +
            "tfLVxPlIN57hXPoD6y8ZsvXdcPBhnKHsRpFikKWVQukjXkFY3en44UdUReHkF6tH\n" +
            "TSJ+kl6kVyfHVFcpvhiIq9M0RO0lSNbIl2nDnMgi4ks94aju7gSIw+t2SQcTAbRI\n" +
            "C87c1b1PlgDEo8KaegPhKXKo8tUfhBMoL9VtOI2XoyrolsDcNi/yyznpc7DpLFld\n" +
            "YMmfp5VORU0NdciZPChCa5clLiFxJZxI68a1oNcki3n4NSmu6yuBevTDufPAcXK7\n" +
            "gC47o9NRgY+7EZvnqAnVnBzJCEG9bWJLcCZrrxz1YzP/BrLsa/VRVu5JQT8jFI25\n" +
            "VifYKW60I/Zc4ApHMj7PjjtAjxcM8h68citOrk7DJr3vpL/XazFyoC64jZNtcSY8\n" +
            "uWjVpEs2qpI/Kpag+3PQQtnSky+MMWdmztLmJ7bnD/R63HFg/Qf2U5U2fmTllnuc\n" +
            "lh2++avCu1X41FFPmQCI0AcQMNxzw3nhHEqd9hPsWvnjfo7crvM6ExHKWzLzdFCQ\n" +
            "XgWruN+wC+b9XY+Rrn+5\n" +
            "=ppAk\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    private static final String v4_nistP256 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: 7A00 864E BC9C 503A 05C7  4687 338C BC25 2B16 66D4\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "xlIEaG0TDxMIKoZIzj0DAQcCAwRixWErG7QLr7ACFxUGjnVHuy1fzaHArCjhXQdJ\n" +
            "cFkly6lxXqpth8a6Ef7ww4xicoCBUkMWDcMDmArolc8pzK7ZzRxBbGljZSA8YWxp\n" +
            "Y2VAcGdwYWlubGVzcy5vcmc+wp8EExMKAFEFgmhtEw8JEDOMvCUrFmbUFqEEegCG\n" +
            "TrycUDoFx0aHM4y8JSsWZtQCmwEFFQoJCAsFFgIDAQAECwkIBwknCQEJAgkDCAEC\n" +
            "ngkFiQlmAYACmQEAAAjYAP9/DDAzA0Ykon8ACI6atMQYYnbIU894956akr64mmo9\n" +
            "FgEAke0o9t/zrH0z1LD7yr3qkW0j+NK2OEy1XIjADrp5wRLOUgRobRMPEwgqhkjO\n" +
            "PQMBBwIDBAqrl9l6YvdrzOWXO4ZFakQCI22HGw4U806IrjGuYFBwdhnu+lGFVFsD\n" +
            "CGMXY2ZhslsSNAJNDrxAP+xeAulDaDvCwBgEGBMKAIoFgmhtEw8JEGTDz6W23cHo\n" +
            "FqEE4bpPaE2vfK5LIsVuZMPPpbbdwegCmwJfIAQZEwoABgWCaG0TDwAKCRBkw8+l\n" +
            "tt3B6HvEAQDN/84YKO0rDGbVyZEuVrOxeHXTC/8DlhHYx9Am5TZu9wD+NJCIzwzU\n" +
            "a4fPISDUJRH+vxAHsRSp4rOCod+tgXsq+7wAANrKAP9dyYnyMEfZcts3i/BZo25D\n" +
            "pqIrfDeZ1ZwP7mMZQ9lmRgEAqKKGBSLnLViyng5Z7Q5BqzW01q7CkLXZZ5IXaNns\n" +
            "0XTOVgRobRMPEggqhkjOPQMBBwIDBC9IY09+8DOpG9aOK2iY6isENu6TvDClVvug\n" +
            "SBnnsUdS3fOhVYYfcniboqrV6+BmfpbwptdGyD0yBUwzfL62/QADAQgHwngEGBMK\n" +
            "ACoFgmhtEw8JEMlGff4yehhJFqEEC15pityd3XNDfeS0yUZ9/jJ6GEkCmwwAAHt4\n" +
            "AQDG3xESM+ryzFUb8c4ldcb5NQ32eg0L1nFgTQEBHNJFpQEAi5xO1ZM4wEOlzk3e\n" +
            "SC3qFyx9K6WQBlpY7TNdgqX8aEY=\n" +
            "=1lGG\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";
    private static final String v4_nistP384 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: C52D CD97 0953 D8A9 3136  509D 20B0 88C6 9BBF 089C\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "xm8EaG0TIhMFK4EEACIDAwTn7aRgEpefzWD3a9g/h7BA6EOVHxcV93BKE2Zf53kT\n" +
            "Yvs13YmY1wTDjsYbHTGTMmm46Q+QSphhiWTVyodykqinFnhmmt/R1L4Z3qQWVBWE\n" +
            "JNyS+swSqPSPQnIEygjqJrPNHEFsaWNlIDxhbGljZUBwZ3BhaW5sZXNzLm9yZz7C\n" +
            "vwQTEwoAUQWCaG0TIgkQILCIxpu/CJwWoQTFLc2XCVPYqTE2UJ0gsIjGm78InAKb\n" +
            "AQUVCgkICwUWAgMBAAQLCQgHCScJAQkCCQMIAQKeCQWJCWYBgAKZAQAApfYBgNg1\n" +
            "Ni0jkkT1TncTslHERidv+teYXTNhtE1Qe4fK9LM/iTruMo3KI5vLQ0yThODrtAF5\n" +
            "AWzr3j/vhAZ0keXBTFiKj+8L564uGZ/Ab2wQUYVNgyrJ4nIylQqjl5v3AoxaQa8s\n" +
            "zm8EaG0TIhMFK4EEACIDAwT2Pz19+CkZouSUqvLtDGKdOfiRoAg2TmVEMkjanwyM\n" +
            "pml7g4XVh0D0WNktvTltHvDepZU4JO5Dse+zC+KlORk6w6KABrC8dujPlO2miFDO\n" +
            "ziqrZClDgkdeJG0F4I/QIbjCwFgEGBMKAKoFgmhtEyIJEBxvr0D4OkYGFqEEB1Ic\n" +
            "cXRzT2WMi+p2HG+vQPg6RgYCmwJ/IAQZEwoABgWCaG0TIgAKCRAcb69A+DpGBgnx\n" +
            "AYDLFfyzoaL02LRlOULvqicJjDuWII4HHQKlWU0bL1CPdVGLizQBPVIrqOE7ne4X\n" +
            "ofQBf3S4CH2TGJdG6joVa5J22VLXhKFVD9MsO7X+QpLcpvpcdWdZpu8pSEIAQ1ck\n" +
            "VwJEAgAAzNMBf34fez/WxNFg7autqSXqSRjeQH6EgJeommuCZg90530WnDRQrm53\n" +
            "a4Ava+p4nW766gGAxzPG8wZ9YiNFWXP80rPaFnVDUvpAzVN6QulNgA9X++PFdnn8\n" +
            "udhXqbn/tjtmhz4ZznMEaG0TIhIFK4EEACIDAwSyypi9tH1VKoyz+whB1u8Poi9n\n" +
            "9G5bWBpQwlkqDMz5P7D0To7m2bnif6qjXfBo0e43NLst7XL9YTXKGiHssGWdvBjW\n" +
            "nUjM9UXWIpuigAEX5Run5Bn/mryfrIL6ocJIrJkDAQkIwpgEGBMKACoFgmhtEyIJ\n" +
            "EB4h59bAP7IKFqEERagGFBZG9V3Kbwc8HiHn1sA/sgoCmwwAAI91AX4hX/+DJLdN\n" +
            "jhZXEiY9SX3jyD97VfvZMTokCB7AfPGZ1GIMtaaTgN/fjhlZcQuoQhsBfjUvF5Rr\n" +
            "S0CgvzBn3v/m72uykFayWZ06cHufSrgkR7UygCjGlVPO5bp4ZoPhW7FUqg==\n" +
            "=UtdE\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";
    private static final String v4_nistP521 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: E17E 59B5 7DAD 1868 AA48  053F C762 4862 050A 405F\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "xpMEaG0TLBMFK4EEACMEIwQAFc+kLfLeUvejNlyhZHH6DF9QGvYD0SzJnTQyecDP\n" +
            "GUk0kUFPx0i2UFh/bFNvfqA5DFG/6WSnWcasSNH1YZAXx8cAUXyISgGSiuqGUztw\n" +
            "/sSkcTSZ0ZJwHEMNlk8BPDdSgPadvy54BxSR+8bxGj+rFmgdB45V/RrXMYNyYAEF\n" +
            "m9HINCfNHEFsaWNlIDxhbGljZUBwZ3BhaW5sZXNzLm9yZz7CwCIEExMKAFEFgmht\n" +
            "EywJEMdiSGIFCkBfFqEE4X5ZtX2tGGiqSAU/x2JIYgUKQF8CmwEFFQoJCAsFFgID\n" +
            "AQAECwkIBwknCQEJAgkDCAECngkFiQlmAYACmQEAAMf/AgQPsBNL2LNlZLHr8REB\n" +
            "TS1ykw0S1RfEHir2XuneunYVxQD+WIK+f9O3lGoA79ojEnbWY3vn5KYL3uIQGTrs\n" +
            "XeJAEAIJAUCmZetIcQD3aixOURerS8gS5pn8jAbSESpzaSyW/EFOCRpMo+zTkZYk\n" +
            "/wFfYayLgtRiEscppMUfyb1lwjiN4vePzpMEaG0TLBMFK4EEACMEIwQBc8xQHGwC\n" +
            "oG04BAmED/5Ju4EkQJC0qTdCLzktWOyHoVplqcUuMR27cf+kHlF65VUJ2OsX8ETH\n" +
            "LHKir9QnPDYSBjcA4Jzq7IBRQrKRF/YKC/UiGI2OMUTB9DF2IpTFWooGEm3WNtY7\n" +
            "r97x3OPNAQjg4Jius/OpbSoOwsxC8Wb44Kw/lTPCwJ4EGBMKAM0FgmhtEywJECtT\n" +
            "oxFC+nyfFqEEeshC8VthZwiw1D6OK1OjEUL6fJ8CmwKiIAQZEwoABgWCaG0TLAAK\n" +
            "CRArU6MRQvp8n5aqAgjS3GZHO7RIJji2zn6Vo7r0C3IXhBx/+ZDmgAEJxZT1WGYR\n" +
            "N9Vjii5tpGIKem6U5ChptHulYvFlK+nvnQfpADFSJQIJAQV7tMmyeTsTw8IOFMAJ\n" +
            "bxaRU+Bn9X3WqcNugzaBhNREW81WFGnRKd2zEK+GY1FEnZvIOj1UoQSrpjPiYAxz\n" +
            "alH9AACLIgII29p8NxOFdMGvvRNcQ5tAr32flqDHD62K3rOYo0qwI1D3OYL6xk6v\n" +
            "cjdoLoLoFa5sDse+4QffjJ9UxsEw+Uye85wCCQEaPDUdeLFLzwcqJQp3X7a3Ok1h\n" +
            "aV3MYf5NYSrTGGVk8KT7xWZOaLCDWdtAF/kteBT/Prg6NpTBZH8fAbItm3KWks6X\n" +
            "BGhtEywSBSuBBAAjBCMEAVBY8RHg8B13ra/HoWvvcNG5gl0yVMhSSSVkjJfyoWyK\n" +
            "CMd3OH4fBti+Z+nllPHPlgAaw/6UMQoNq242LWtr+Y/XAX0G2snCs5dWG+biNaee\n" +
            "QWvRkL/26KVwAmV1AsIfY577TXva/0y7Dj3hnAO/+x383cCAqwAsjsXrDWoscuf/\n" +
            "LLxOAwEKCcK8BBgTCgAqBYJobRMsCRBcxJwrVFEM0hahBLBO62CL4VLDpYpOZVzE\n" +
            "nCtUUQzSApsMAACuNQIJAQz2sTSbfeERmHa97smijy+Kqt8ZtDQ+k7vXOMSFGlVO\n" +
            "mz84Kzs1+it62a+PaNPM1UnrcRE4NmppCtnVIS6kV8z7AgkBMcH5EeBCe10fbqdm\n" +
            "BI0at8JPONR1s7yZ7R7z+G1EsnUkF+t3dzQrCOBlXI83KC+hb5eOXKURkfiZgdpO\n" +
            "oR99QtE=\n" +
            "=1kU8\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";
    private static final String v6_curve25519 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: 075CE2AD 721B3A3E 877329F1 24131A25  A43876BC DD09943D\n" +
            "Comment: B1EB5C73 4E98EFEF\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "xioGaG0TTxsAAAAgAhlYynX3JdyxowVByJP29cYt7tTRVtMEHzj3ctWRaNvNHEFs\n" +
            "aWNlIDxhbGljZUBwZ3BhaW5sZXNzLm9yZz7CwAIGExsKAAAAUwWCaG0TTyKhBgdc\n" +
            "4q1yGzo+h3Mp8SQTGiWkOHa83QmUPbHrXHNOmO/vApsBBRUKCQgLBRYCAwEABAsJ\n" +
            "CAcJJwkBCQIJAwgBAp4JBYkJZgGAApkBAAAAAD2DIFbG7ai9HSJKlRqtv1c8KTXc\n" +
            "7PcJeF0wjKcqxrSCp2Gwhd4/CdfHEeDWxE7x0QRuXERQJLPwae1dYITvsBrk7cR4\n" +
            "DpMe33Kqaj2KuWsPWhU5efaIZ68hxurXPH1eHjpXAc4qBmhtE08bAAAAINBT+USX\n" +
            "w4Y/WFM6ArUXFrjZAV8+FyUa2aZJps3zZmuiwsB1BhgbCgAAAMYFgmhtE08ioQZB\n" +
            "a272wKwg9+XBs4b15pDGecNCy5kqOeZzJrWLET546gKbApkgBhkbCgAAACkioQZB\n" +
            "a272wKwg9+XBs4b15pDGecNCy5kqOeZzJrWLET546gWCaG0TTwAAAABLmSA4FypT\n" +
            "lEiKE1Jd8isuE3+gXWRZO+/tDkrwsar5dTUFysv0NR+LDOYy/a/HbPCDhEIKjBcY\n" +
            "qzTP+3R2ZZe2rGkE+77sht2j1YIcBlzm+t3HA8V20iFn4rpWHy0571hVpggAAAAA\n" +
            "Bt0gnCR4K4AuIH7fZr4b9BVJ3k4kIvdk9X7S25yyjw6JxZH17fluPiJQVCu/m0be\n" +
            "lj0dfqCHfTPJ2iZl3RLu0e5mBoolbN4JostQ9FzVi9dZ788jYXvnGIUnoBRu57ZO\n" +
            "n3UAzioGaG0TTxkAAAAgDRJh03RIU+tZWnyRk684h/GqvO7zL8LJFxL/lHEruULC\n" +
            "mwYYGwoAAAAsBYJobRNPIqEGo8G75Tf7oWt8oa59iQ32S6uKCXrpadeS/Xjdt1iE\n" +
            "zyECmwwAAAAAQPQgn2hzfU/3y0CkbuuHn0+jdFLJgs8hFpDx0v1cLpiAKvWLBIZI\n" +
            "sixI3KLQxiqvxZQXCg+/dQoNO1se4XZ/g6KLvGLzJ6BC5MpUfOfJoGc23u68G2K3\n" +
            "WpYP1EQ/UjACBT4I\n" +
            "=Uq9u\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";
    private static final String v6_curve448 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Comment: 212F1BC9 7FF7DBF0 B6F18D83 F59BB2BC  075F26C3 2CE5F150\n" +
            "Comment: 0B770469 11A0A196\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "xkMGaG0TXxwAAAA5ffh5M4YFiH+SEFbP8SeW7FhJns/56XYfUjk28nejYWQgl4Fd\n" +
            "vihxLAtryw6iEscMoudI7NsUWC+AzRxBbGljZSA8YWxpY2VAcGdwYWlubGVzcy5v\n" +
            "cmc+wsA0BhMcCgAAAFMFgmhtE18ioQYhLxvJf/fb8LbxjYP1m7K8B18mwyzl8VAL\n" +
            "dwRpEaChlgKbAQUVCgkICwUWAgMBAAQLCQgHCScJAQkCCQMIAQKeCQWJCWYBgAKZ\n" +
            "AQAAAAChXiCvjG1wSHZzZwaVEnfGyMGrhb/l9mjULQFaQmdEgJ33i/iEv6MQYaBS\n" +
            "nPRCcI9GLjq/kkz957EhvBxeM1K5OHUAhHLy2AY4ReKB/N5Xz3D7pAivqsQzq/DS\n" +
            "gIKfGQxjEt/QPy7C+qsNNHsss4l2mo3ugdV5mQV4DcBzeHJcz7hMce00HRIVRemw\n" +
            "JuPhh3gEFN8hAM5DBmhtE18cAAAAOTs6skyf+PcX3A+rsPMjmEGVc1IqJw4xOqoZ\n" +
            "gPghbYGGqBrYAqzr//xKshyewSMOH5fmGX8aQyoPgMLA2gYYHAoAAAD5BYJobRNf\n" +
            "IqEGC4EDngLrM73LIg5bZQKYVUAM98vVI86Qq6SE4mUxlxkCmwLACyAGGRwKAAAA\n" +
            "KSKhBguBA54C6zO9yyIOW2UCmFVADPfL1SPOkKukhOJlMZcZBYJobRNfAAAAAHuS\n" +
            "IBQQaYywrO5u+n8R7Xcb+WoQ7FtHUmHpW5triJ/tkwfnufiC56CD465EyLJ9g+Mm\n" +
            "IA+5n03AxeH0Yk7afFBgRw9pQlPb2/1P66iexPV7445sjJ9jCK2NTJaAd/H6R+CW\n" +
            "iCYl5VCtkoryXNN4yad6OVt+TrEQHCF4vRUpAUAF30EO8LUuUsB0F3D0D0aDglBi\n" +
            "tiAAAAAAAAR4ILw9d7lfCTtaOpBEr0YHo8kPzVcBxdDbUfo9UAqScZhwCbSVrANI\n" +
            "CJw614Ss3WhTuV+l465zwccF2xh0D+VAue1AwnwnQzp518zFqTXJmOUcs7YuPWyU\n" +
            "iQEA/tc+jUg9XL6EQ/5UYMhfj7nO/b8uZuD2KYPtc2e8X3mk1is05fhB9JSOOGib\n" +
            "d6su8g3Pv+HQGx4AzkIGaG0TXxoAAAA4WAHz84E3zX2mIoVBETPWdzvumbTqFiUM\n" +
            "uiI96b6XmWi21G8F/BdpWs1Gg347x7PbVWfq9SD7t6TCwA0GGBwKAAAALAWCaG0T\n" +
            "XyKhBq9bQBVplmkyzKWaEqIweNfJ85ls16CfR2rNXYYs2vDyApsMAAAAAPQUIKzs\n" +
            "xWkiYn0kM7FsHGMlMGET0wrdKg4F45dGCHDUHeUZSusp5Zs7okmY6HP4tePSMuMq\n" +
            "9whjVqimGN6Xx0ybErP/ku6jExwN6QtYohZempWCZXv3SJteGI8ADuVKmcNT9MBN\n" +
            "ic3vixr3vjkXsuUwBQDGDb7SRfA7DGh4mXxAaB5gUwQC+wSIG6D7gIP2Hz0fVj4A\n" +
            "=9WFq\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";

    @FuzzTest(
            maxDuration = "60s"
    )
    public void verifyFuzzedSig(FuzzedDataProvider provider) throws IOException {
        byte[] sig = provider.consumeRemainingAsBytes();
        if (sig.length == 0) {
            return;
        }

        try {
            List<Verification> verifs = sop.verify()
                    .cert(v4_ed25519.getBytes(StandardCharsets.UTF_8))
                    .cert(v4_rsa4096.getBytes(StandardCharsets.UTF_8))
                    .cert(v4_nistP256.getBytes(StandardCharsets.UTF_8))
                    .cert(v4_nistP384.getBytes(StandardCharsets.UTF_8))
                    .cert(v4_nistP521.getBytes(StandardCharsets.UTF_8))
                    .cert(v6_curve25519.getBytes(StandardCharsets.UTF_8))
                    .cert(v6_curve448.getBytes(StandardCharsets.UTF_8))
                    .signatures(sig)
                    .data(data);

            if (verifs.isEmpty()) {
                return;
            }

            for (Verification v : verifs) {
                System.out.println(v.toString());
            }
        } catch (SOPGPException.NoSignature e) {
            // ignore
        } catch (SOPGPException.BadData e) {
            // expected
        }
    }
}
