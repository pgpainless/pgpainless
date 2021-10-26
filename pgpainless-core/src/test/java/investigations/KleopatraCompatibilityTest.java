// SPDX-FileCopyrightText: 2021 Paul Schaub <info@pgpainless.org>
//
// SPDX-License-Identifier: CC0-1.0

package investigations;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.MessageInspector;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.implementation.JceImplementationFactory;
import org.pgpainless.key.protection.SecretKeyRingProtector;

public class KleopatraCompatibilityTest {

    public static final String KLEOPATRA_PUBKEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "mQGNBGF4StQBDADgAGvvtzCrSa5I9/jIZq0SKxoz7Hz61YM2Hs/hPedXfQeW7lrf\n" +
            "qutyXSIb8L964v9u2RGnzteaPwciGSyoMal5teAPOsv6cp7kIDksQH8iJm/9FhoJ\n" +
            "hFl2Yx5BX6sBtoXwY63Kf9Vpx/Std9tN34HHI7zrbO70rv6ZcDPFHyWoVdoDZOX1\n" +
            "DWbBnOP3SoaNaPnbwEBfEkPwyN/NsnxTfe+IsCYC2byC3NZwYA5FscWFioeJ/UpF\n" +
            "HMgZ6utn9mfTexOYEE0mL1mhrc7PbRjDlNasW3GLrpeVN55anT0jvtNXulG4POzG\n" +
            "fJ8g3qddcbTXYhQItjurBlkYLV1JOhdCN83IJRect4EIKBkLuEKO0/a7bE6HC7nr\n" +
            "PLw9MWGgcnDe2cTc4a6nAGC/eMeCONQlyAvOIEIXibbz4OB0dTNA5YYTMBHVO7n0\n" +
            "GbNg8eqw+N+IijboLtJly+LshP81IdQMHg0h6K3+bfYV0rwC/XmR387s+pVpAp5k\n" +
            "Lrw8Rt+BsQSY2O8AEQEAAbQhS2xlb3BhdHJhIDxrbGVvcGF0cmFAdGVzdC5kb21h\n" +
            "aW4+iQHUBBMBCgA+FiEEzYzHEulLyE5PkaUp6EVgKKoTP1kFAmF4StQCGwMFCQPB\n" +
            "7cwFCwkIBwMFFQoJCAsFFgIDAQACHgECF4AACgkQ6EVgKKoTP1nClwv/exOrk3H0\n" +
            "aKOqwB6gMtA9bOJgYG4Lm3v9EM39mGScTJgAaZMlJIVMZ7qBUCEbw9lOJMZLguVm\n" +
            "VJN8sVYE6zNdPGxmQLLciXDheGIdmQDi/K1j2ujKWUVZEvasiu7pO2Gcl3Kjqaeu\n" +
            "dpvKtEDPUHtkqzTQHgxpQpSky58wubLyoX/bNnCky3M/tu774kJ2HGHTy6S4c1KH\n" +
            "f6k4X96vP1V7yoKp+dukYLXwtm73JAi7nX/wOmoQI4I60fs26ZFDpoEkAZVjZtj6\n" +
            "qfT9unS+XZeklc0siaZ5wZvVuSGWcI4v4/rA/ZU9KjDriatEu0ZzE/Xll1MHQyh4\n" +
            "B31zjwP8LmLSrNHMLmT+7nM+nCfCoo71uZGkuuR0sKa6bToBUOls1olRmKaZf9NS\n" +
            "JjW0K0xL3TEzduM7h+oDNLf5bSSZFoDGwsHRW6E53l7ZDe7tOH+ZGSDuCbIVu4dQ\n" +
            "6k0NVMFI+gxTwQU/4RS3heRvn739P7VRLyUl4gX0/q8EanHPQX9NXIuSuQGNBGF4\n" +
            "StQBDADMeuyDHP4np/ZnfaHXKLnz6C+6lrF/B0LhGXDxvN+cCpFvybmqGZ74DOkK\n" +
            "VXVlmXjvb22p6+oOD163/KOqfrjKT/oeVhMglMc2raNy5+XWHcjKBhprxbX9bIhr\n" +
            "QEjmvP57pIfQ83s1dgQsWlxIwX1g86X04u6tnG+fwNdGrhZwcbaivJT5F82uKKIq\n" +
            "gtDbqcUtqOQpg+zUO2rdbgjWw5LZPBiC/dHkWydGvzWrnAgDmVAsJita2F+Pxwmn\n" +
            "i3p5qU2hBJmJuVo15w6elST1Svn3jim5gqbXXhh2BwDSDPEp0uRZlV6r9RMlH+js\n" +
            "4IvKiveGzdXTzmbPl8U+4HHynPM1TWRxCaXNF4w4Blnlqzgg0jFXVzV0tXk1HJTc\n" +
            "P4Lmmo0xpf5OEsbCZv61qDJO20QMHw9Y9qU/lcCsXvmtFfEDTZSfvIEAlpo7tvIn\n" +
            "3H94EiVc5FNpRfWrngwPnwt3m3QkmG3lkd5WnxuyjH/LbKMtuBC/3QuKNrrySvXF\n" +
            "L4SL51cAEQEAAYkBvAQYAQoAJhYhBM2MxxLpS8hOT5GlKehFYCiqEz9ZBQJheErU\n" +
            "AhsMBQkDwe3MAAoJEOhFYCiqEz9ZkhsL/itexY5+qkWjjGd8cLAtrJTzhQRlk6s7\n" +
            "t7eBFSuTywlKC1f1wVpu5djOHTPH8H0JWMAAxtHQluk3IcQruBMFoao3xma+2HW1\n" +
            "x4C0AfrL4C00zxUUxqtmfZi81NU0izmFNABdcEHGbE8jN86wIaiAnS1em61F+vju\n" +
            "MTMLJVq56SQJhWSymf4z4d8gVIy7WzeSuHnHcDbMcCfFzN1kn2T/k5gav4wEcz3n\n" +
            "LizUYsT+rFKizgVzSDLlSFcJQPd+a8Kwbo/hnzDt9zgmVirzU0/2Sgd0d6Iatplk\n" +
            "YPzWmjATe3htmKrGXD4R/rF7aEnPCkR8k8WMLPleuenCRGQi5KKzNuevY2U8A4Mi\n" +
            "KNt5EM8WdqcXD3Pv7nsVi4dNc8IK1TZ4BfN3YBFQL+hO/Fk7apiqZDu3sNpG7JR0\n" +
            "V37ltHAK0HFdznyP79oixknV6pfdAVbIyzQXk/FqnpvbjCY4v/DWLz6a4n8tYQPh\n" +
            "g94JEXpwhb9guKuzYzP/QeBp4qFu5FO87w==\n" +
            "=Jz7i\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n";
    public static final String KLEOPATRA_SECKEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "\n" +
            "lQVYBGF4StQBDADgAGvvtzCrSa5I9/jIZq0SKxoz7Hz61YM2Hs/hPedXfQeW7lrf\n" +
            "qutyXSIb8L964v9u2RGnzteaPwciGSyoMal5teAPOsv6cp7kIDksQH8iJm/9FhoJ\n" +
            "hFl2Yx5BX6sBtoXwY63Kf9Vpx/Std9tN34HHI7zrbO70rv6ZcDPFHyWoVdoDZOX1\n" +
            "DWbBnOP3SoaNaPnbwEBfEkPwyN/NsnxTfe+IsCYC2byC3NZwYA5FscWFioeJ/UpF\n" +
            "HMgZ6utn9mfTexOYEE0mL1mhrc7PbRjDlNasW3GLrpeVN55anT0jvtNXulG4POzG\n" +
            "fJ8g3qddcbTXYhQItjurBlkYLV1JOhdCN83IJRect4EIKBkLuEKO0/a7bE6HC7nr\n" +
            "PLw9MWGgcnDe2cTc4a6nAGC/eMeCONQlyAvOIEIXibbz4OB0dTNA5YYTMBHVO7n0\n" +
            "GbNg8eqw+N+IijboLtJly+LshP81IdQMHg0h6K3+bfYV0rwC/XmR387s+pVpAp5k\n" +
            "Lrw8Rt+BsQSY2O8AEQEAAQAL/jBENv3Iud52umyzrfI0mZ9cFUHR994uqp67RezR\n" +
            "Y2tpH/0IMCGY2THj2oktt3y5s/OFJ3ZCrhdo9FcHGKXHSa7Vn0l40GIPV6htPxSH\n" +
            "cz1/Dct5ezPIxmQpmGfavuTYGQVC3TxQjkJEWTcVp/YgLn0j+L2708N6f5a9ZBJa\n" +
            "E0mx8g+gKqLCd/1JGp/6+YI39/q/cr9plqUoC31ts7dj3/zSg+ZCV4nVHwnI0Np4\n" +
            "o0iSoID9yIaa3I0lHwNgR1/82UVEla94QGKSRQqjTrgsTLPFIACNtSI/5iaPdKZK\n" +
            "a01oic1LKGEpuqpHAbnPnCAKrtWODk8B/3U4CABflXufI3GTYOZeaGZvd6I/lx/t\n" +
            "HQcg5SKE8vNIB1YZ2+rSsznAFmexaLjPVG3XhGQdBVoV/mmlcI71TUEcL9kXYMh6\n" +
            "JnwH5/F2kG9JAXC+0Y3R9Ji+wabVGMUHxugcXpQa0d/malCZaS/dviDUfZ1KbDjH\n" +
            "Jlzew7cmfRtiw4tfczboekeSbQYA6bh6IFqQlcW7qj34TAg8h8t34Q2o2U0VMj96\n" +
            "OiG8B/LARF89ue4CaQQMQt16BHeMhePBAhPCkkCEtmbXremHsrtn6C149cS9GAEt\n" +
            "fSAHVGedVDHzke/K84uHzBbY0dS6O6u2ApvWOutgWpB5Le4A7WTslyAdLWRZ1l69\n" +
            "H2706M9fgGClVsQByCNVksDEbOizIlAkFOq0b39u8dnb063A9ReAuk/argCA7JHU\n" +
            "j3BFIF5crIn+YrWl6slFuoXGWTXlBgD1WsVhU4hXJ5g35TOso0rEND/wHrjW0W4F\n" +
            "LViA5yAt9sVLNGgm9Ye3YSVIHId6HiJQZmsWJb81WD5dvBLl74icZmfSWtRTwvCZ\n" +
            "0k3rYlu3Ex4bQUwoyhSlDoPJ9YMaumd1yaM3nMeyrlaHYIpV8NtqSuqJc7i2iNX1\n" +
            "3s9AotipHYEUOlsp936bNEuh0m8xXEZ2C8qjpNenymg8XfNd/IH2M4Sjzz+pN5sS\n" +
            "gQt+pQhYFnW0Gersb/X3OsAtLtRE5kMF/3v7GAz7usMcajqbh9qB+Ytp4n1u3aQC\n" +
            "ck1exVOwdLDZgsHfojO1SEFd3IafO01xp+TmS8qIoZvKJegM+qq9px1PHSTRnb4D\n" +
            "8tuBxtdoUE7n+g3Li74je7+DEdcq6g9ZjgyeosCHGItUwTcCMqnHa+ikjQjsnnzu\n" +
            "eSwvVSfMJQYyZrZ5qYgQZKcovkFDvgXiC/jqfDd6GeAfbxzL2cyAYWvUdGln79O3\n" +
            "Tc7ZWd0Xn6IaMPVPRBvH4RsaWqFdO0pIOuH7tCFLbGVvcGF0cmEgPGtsZW9wYXRy\n" +
            "YUB0ZXN0LmRvbWFpbj6JAdQEEwEKAD4WIQTNjMcS6UvITk+RpSnoRWAoqhM/WQUC\n" +
            "YXhK1AIbAwUJA8HtzAULCQgHAwUVCgkICwUWAgMBAAIeAQIXgAAKCRDoRWAoqhM/\n" +
            "WcKXC/97E6uTcfRoo6rAHqAy0D1s4mBgbgube/0Qzf2YZJxMmABpkyUkhUxnuoFQ\n" +
            "IRvD2U4kxkuC5WZUk3yxVgTrM108bGZAstyJcOF4Yh2ZAOL8rWPa6MpZRVkS9qyK\n" +
            "7uk7YZyXcqOpp652m8q0QM9Qe2SrNNAeDGlClKTLnzC5svKhf9s2cKTLcz+27vvi\n" +
            "QnYcYdPLpLhzUod/qThf3q8/VXvKgqn526RgtfC2bvckCLudf/A6ahAjgjrR+zbp\n" +
            "kUOmgSQBlWNm2Pqp9P26dL5dl6SVzSyJpnnBm9W5IZZwji/j+sD9lT0qMOuJq0S7\n" +
            "RnMT9eWXUwdDKHgHfXOPA/wuYtKs0cwuZP7ucz6cJ8KijvW5kaS65HSwprptOgFQ\n" +
            "6WzWiVGYppl/01ImNbQrTEvdMTN24zuH6gM0t/ltJJkWgMbCwdFboTneXtkN7u04\n" +
            "f5kZIO4JshW7h1DqTQ1UwUj6DFPBBT/hFLeF5G+fvf0/tVEvJSXiBfT+rwRqcc9B\n" +
            "f01ci5KdBVgEYXhK1AEMAMx67IMc/ien9md9odcoufPoL7qWsX8HQuEZcPG835wK\n" +
            "kW/JuaoZnvgM6QpVdWWZeO9vbanr6g4PXrf8o6p+uMpP+h5WEyCUxzato3Ln5dYd\n" +
            "yMoGGmvFtf1siGtASOa8/nukh9DzezV2BCxaXEjBfWDzpfTi7q2cb5/A10auFnBx\n" +
            "tqK8lPkXza4ooiqC0NupxS2o5CmD7NQ7at1uCNbDktk8GIL90eRbJ0a/NaucCAOZ\n" +
            "UCwmK1rYX4/HCaeLenmpTaEEmYm5WjXnDp6VJPVK+feOKbmCptdeGHYHANIM8SnS\n" +
            "5FmVXqv1EyUf6Ozgi8qK94bN1dPOZs+XxT7gcfKc8zVNZHEJpc0XjDgGWeWrOCDS\n" +
            "MVdXNXS1eTUclNw/guaajTGl/k4SxsJm/rWoMk7bRAwfD1j2pT+VwKxe+a0V8QNN\n" +
            "lJ+8gQCWmju28ifcf3gSJVzkU2lF9aueDA+fC3ebdCSYbeWR3lafG7KMf8tsoy24\n" +
            "EL/dC4o2uvJK9cUvhIvnVwARAQABAAv9ExmcWWGY6p1e1StACyKrvqO+lEBFPidb\n" +
            "Jj7udODT8PXFFgW9c60cU0aUHLn/fZ5d/zI6XSKYj02nkaoQo6QIoM/i/iMY0En1\n" +
            "aHRvDb7+51w1iDa/uwy8biVNgi8pYBw2l9gLiQdlR94ej6y1GBAIJR6ShD26VmSE\n" +
            "F2O3osuEybtleEKt660/MiMWMBWzaqwAq2jY6c5/4xHVw+87oMv4k0AbeLOQKojK\n" +
            "h2o5mi5jSpVvOWCAsOYAhHlEEUQPDFQ1rbJ3P3XcRZE4EIxP2eKDyfyOXRTihLDl\n" +
            "/9hqOf57wo0C43bnc1BkD6sk+ptKgUifpUHHejg/i7HINFivh7jCgCtoskf2P9BL\n" +
            "WFuaPZVLQSVE5X2PsgeIYK9/eGeNxfXgtwRyUd8DtBge11tsMaENUTm39p36my2K\n" +
            "jBgoEdBIQo1Mpi1EZba+L6pyw9bPFnj5H+opSe+X9/spkS9DyPOPGY7rCSTgv+7q\n" +
            "Ph2WbtRRJslitLEjT9tNgwMRGWsgdbcpBgDgzujDUQb1coCdgw1gsQSTPir9hJxF\n" +
            "Q+2DAbGpkqiYayHJqH7T9wGhiY8QoqLIejNawkrel4yTtYmM7pgtURWrkzz/jHAT\n" +
            "3NNRTyvFqMmjwOIoV83tW8247uA8eofc981wEVayJ4y/KDcvU04FBrjCEoOUQMXw\n" +
            "Ychr4cGiEckGBxAib6fVxjsU3PUIuUDpm9NC53Rc0GmwlduiZSJqRZQRgytLxWdM\n" +
            "Va4c5oHdc0qpjCgk5qkW/09lI5kxTlMk3E0GAOjZ+HSQV8rI7qu7G0Qno9MP0Q49\n" +
            "Qo5Hf4uV+I/6Iim/Eq5LWKmmairIob47jLtmhoIo7LArTm+9NsThFidc6wjRYgtT\n" +
            "kGx4KUTEl8d0/mHV8GBzNNyRM7UOoLVjgf4tljFa8d2hQNMXZyBsIkLyoL6cL2sx\n" +
            "aMZWl9jjh0bYE4TiTDIO1cfddxGjCPG9i12Z+yMl5p0g+r+IUAbuSh4+Yo7PUIKF\n" +
            "8v+mqZRC9M9C/T/qOAB2gL2vDEZ4TdLAZfYUMwX9E/I1e0gHPlqXmQ/znTkjuCXd\n" +
            "JopVXmvvku8SvVFb4pcW1k5Tk3iEj7nilQ64I5bONFUot+qKTtxAM2Fwxo0EjFZD\n" +
            "TCP5RbY60iJcnhpk5mDGD41O1xe2HBkJw8dC5xUr1pPs+7Y8gMXN3qK4JcrLfLSO\n" +
            "pOb623ir9jtJWLjv1wOvr7KsWZxg8XOQq8+AkEprUjb8v8WsJY5c7L8vSJ5OYlOP\n" +
            "gv9Tj3MVmV1jGhH9pR+zGcclyathY3Ytloy1zZxR3WCJAbwEGAEKACYWIQTNjMcS\n" +
            "6UvITk+RpSnoRWAoqhM/WQUCYXhK1AIbDAUJA8HtzAAKCRDoRWAoqhM/WZIbC/4r\n" +
            "XsWOfqpFo4xnfHCwLayU84UEZZOrO7e3gRUrk8sJSgtX9cFabuXYzh0zx/B9CVjA\n" +
            "AMbR0JbpNyHEK7gTBaGqN8Zmvth1tceAtAH6y+AtNM8VFMarZn2YvNTVNIs5hTQA\n" +
            "XXBBxmxPIzfOsCGogJ0tXputRfr47jEzCyVauekkCYVkspn+M+HfIFSMu1s3krh5\n" +
            "x3A2zHAnxczdZJ9k/5OYGr+MBHM95y4s1GLE/qxSos4Fc0gy5UhXCUD3fmvCsG6P\n" +
            "4Z8w7fc4JlYq81NP9koHdHeiGraZZGD81powE3t4bZiqxlw+Ef6xe2hJzwpEfJPF\n" +
            "jCz5XrnpwkRkIuSiszbnr2NlPAODIijbeRDPFnanFw9z7+57FYuHTXPCCtU2eAXz\n" +
            "d2ARUC/oTvxZO2qYqmQ7t7DaRuyUdFd+5bRwCtBxXc58j+/aIsZJ1eqX3QFWyMs0\n" +
            "F5Pxap6b24wmOL/w1i8+muJ/LWED4YPeCRF6cIW/YLirs2Mz/0HgaeKhbuRTvO8=\n" +
            "=cgLL\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";
    // signed and encrypted
    public static final String KLEOPATRA_MESSAGE = "-----BEGIN PGP MESSAGE-----\n" +
            "\n" +
            "hQGMA2gglaIyvWSdAQv+NjugJ3Sqk7F9PnVOphT8TNc1i1rHlU9bDDeyZ2Czl6KA\n" +
            "YXwSP5KmwgTJH+vt9N5xrbKOGCuSCJNeb0wzH/YpQHLL5Hx5Pk0KtNH8BCevApkM\n" +
            "Rcn4EKiXMmTFyib0fCPlqvEvqdD1ni1IliHNLxR/TYCSxbmu3TqPie70PiLsB32l\n" +
            "6QKDi1U3HftsZOLLgIPbd1IqnSMeT3E15oD8LTQe3k/CV+huA54wrIeqDxfJpcAu\n" +
            "rvb4rLVvGmaF67FXekMEDjD3cdk2m6WJ8c1myh3EUpDRlMPobhgeEV+h28heGuhu\n" +
            "g2Id97DMfUhxypGbQ/rlwHE3UMvdW3YS0KRT7UfPee0F2m737b/aWO341LOzJz94\n" +
            "xggPafIC6IseQQVZirocG1CLl0lauWZoXbfmzrXCT+YGNuaNjlE01BYPBjgEygle\n" +
            "7Kur60YkB0H6fACskcudWDRFTsjEgIZa3riHou7XmvqupvJC+hyYdH3QqyFMvdix\n" +
            "03/E9ePUs051Bvzn+a/dhQGMAwAAAAAAAAAAAQv/RtljqQ2BsB0KkdzZtnfY+CZZ\n" +
            "PBYvloxplK+Bs8aoLVujyI7g6weOvFD49tSowsvJ//DleDpcKe4UZA/WRj5HlB1J\n" +
            "5zLK5qlWb8El6QKlwEKB02zHDv244Bm9ZROnSK3CrEqRcfdBQIx4ThEOZlG0cE60\n" +
            "iTbrda2SYUDpHh4Re/qhw/wvc0uUf+59u8WU5AIpgfLBU2fNEjOr6LMIsR3Edvf8\n" +
            "zIFUrHlfvKQaAnZYU79dA0ZnTYgLiwMWB19nvhnSIdWAC3tJUsiuEIzEzA+vVbG/\n" +
            "YrTOMR+vFm+dVOcVanzn0vnV0n8+np1kM1V2JgGRKV6XybS1oUbNPvpv79FBgfPi\n" +
            "F3WghBHZf9lTaj4w7LtQSojvC0YxSoxfTif/MMxNZUoexQbk0jE97ibeFk6rqrBn\n" +
            "46G2WbrrReDyOUekSkM5MQ/bZ1GJuFfC+kGyHETBejsfn0ZKa2RUla9k3vYFcDJC\n" +
            "Et7Vwv81SF4yzvSwiV0rFx1RcyZaGlJumjCkqaHHhQIMAwAAAAAAAAAAAQ/+KTsY\n" +
            "vnPMOmjmLqu7BQwx3jUaEmCXTurv5XHMbAEcq0UAwHJ/XAcJe7B1707Fu1sSJJjV\n" +
            "3rJVHGUv7+APg5/vALx/FGlKk/12M8NhgOreLCLa/vQ9NmNrcfqGQdZtpk6OQxLv\n" +
            "DcnCbUjyTO2IFRjmzEy8d8rne/FMC1MZD9hY1IboJWk5fN1NCsIIbPn3OSqVIaa1\n" +
            "9fJj6D7SGacraBNJwl0x22ipV4yLtpo2DtnPJGK4xgTm0eW7eUK3nIfC/foHEgxG\n" +
            "Bny1axnKqC9TFhAQ7Eo+Wh9eAiXtFBY7po7tfYmhb6mHBMAfYsVvCCyLNqUbXiV9\n" +
            "kXWMBf0yxtNQlkx1jK+iqfGBm3EfHKncXGfl6zxwkh1FZXcY2EyCavkGND+3Gexg\n" +
            "vbCUltulq1Fv1WjOGz9Icc5pK9AyjUuc/AQ4k7WhCVhCmbpsb/Cq6LsiqOC219dE\n" +
            "r5TLGr+K1289PVOgbd06BL5NVP6qeO5fyWUA/Bs+exxqEDKce0f0ppKkcGNAv9p/\n" +
            "Lg57FxT8aYVBgSoTv1DASquZANrO3kp7M3nC5lVzUldz8aS4YEirLLTF0MBnZEZ8\n" +
            "MRcG8h8oSKozw+cuJXNF+bFiKM0wwRyw0AXGt69/lrPlWKMCfuK3n8vqxVPJ78JD\n" +
            "ut8xHNWelqS2uO0qinvfbBcKzptYUm8ctNbHlSLS6QEnmjoiF/jobEDWsp6yBaym\n" +
            "o7h9VQrmCKjKsoQzoF5KYHW87BLb2YRnx5WwTvN1BvZTNqNjkm9tuDTIwhTUx/L/\n" +
            "B8l+KqpGcrmsldQ/pF/W3m2mFlsqpb02uWJSpXQ7NEavjvPThKPJHUnni4YtCg5b\n" +
            "v8Zy/zvYgGj5y4DDjM84Xw/HcMdyHsWIcGosZ6W/jJhO7sECXqS6HoF5zFsIBPX9\n" +
            "dEM4GS5TapLe0s7DyC0bK7VbPgLMBxPmbBSVp3O72qKpvgc6PAggTJHNhd6MLsJA\n" +
            "JAiAOF/KNNZxSdMWIXqMyMviSPeU9+KclOG7iiR75Q5kIbpj9hWo5ullxr6XrHl2\n" +
            "HFR+5jnmbSNwz/cf0vwkTnNG/Crofyy0kPTfGp5Ku4hp0wIhWXM9f8m7tuoxI3ep\n" +
            "uNwB7FOs3xemsxAmoufyWcsyxnVf/3OJLWejIcIK1v3NmoiSxFQXl2cmiRVLTtAT\n" +
            "oNjUT9QDQiyi8YR+CepV6RnBSmRomr7HfRAoACaCg6ToaXm0Dc8OQSge2X80ifdD\n" +
            "NUcfhQAivaVAqhAogUIaPp9yqwTWaZ00N5cPH4HItPJtukb+Fsove2SoF+iPQre6\n" +
            "hDjZCNyfUjT+wnca315nN+9D6Z1JgV5YEM23sFKp4M732Zdb5JlR0DXfDEuQH1NL\n" +
            "hXOcpr9LpAvASH7weiVTEYxNz5KzFkUQA5YKLLeDwtcK\n" +
            "=MgH4\n" +
            "-----END PGP MESSAGE-----\n";
    public static final String PGPAINLESS_MESSAGE = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "hQGMA2gglaIyvWSdAQv/Y9Wx763qAM95+teCUPPNRc5Iwqbc5uFjxfbcwsHIWdiZ\n" +
            "n2wHNUmd2dUqYgpqOcBwZ/fUJuoHj/uXKZ1pbz2QSVYaL9MulKpgWiVAo0K2w0Oc\n" +
            "97KfZ0d66tcZIhslVpZW06+lXuwMyjjjExe32fAkPFnYyTNORljyYlb/RDSkh7Ke\n" +
            "Q+48fLR2kitV0WyRZ+d9cMfx2+D2gWYiaFGek9SrhI8L+nNd4UKvM4K4sSq4JHYf\n" +
            "DCxGPWYOaTculuX8dfDh3ftHbrmL2Ca7Iv4NB0kSduG8Gin2OWyeSIPIwpF2ci9g\n" +
            "cIBssAYhmS88FQit5pW9z2RZ/e9XmYIP++kz3/EdI6DqkiPUv1fiHTrJBC93LvVg\n" +
            "pq75h9RNFuUlqR09SVuB/uZB6tYgv77vy5lPFo+wmLjM41aS4+qI1hBI3Ym4XTc1\n" +
            "spPA0sEHtQTQ/xRNYqGpwunJniMF3ukWpOB6UNvQld+p2lj8czexhEAcne1cjey/\n" +
            "f0/WUnluSt0HIg8Mnd7s0ukBhb4YxjvARjuqi6PikGz4JPshRwB8dPtS9FQiRxL7\n" +
            "obaPHXlmLwohEtT3akzoIj/9C3Y7qnfreSllDgRDxRVFPXy5QnQqpsTy2JuJ4cvo\n" +
            "p55RE2kyJ3vBZlB6T53pSgC00hQnNxoqgy7aejRItlec7zx5DnEg8t4rA7LYEGLT\n" +
            "MBLWbTRc/njH6GTyc/3x7j9k8V83exqpF6fXrE3GP1C3fBxHY2S9/5BFAlzimplz\n" +
            "Mow4S15D04EllRRk6f9HKY598xS4QlDEW/f3utwkQ8+/lNqesVuV8n76WDldMv2O\n" +
            "5gTqAZ/pKhDKRLY6km4B2+2IAt2zg+V141wryHJgE/4VyUbu7zZxDIcDouuATQvt\n" +
            "wNMnntqy3NTbM7DefSiYe9IUsTUz/g0VQJikoJx+rdX6YzQnRk/cmwvELnskQjSk\n" +
            "aGd92A4ousaM299IOkbpLvFaJdrs7cLH0rEQTG5S3tRJSLEnjr94BUVtpIhQDo3i\n" +
            "455UahKcCx/KhyIzo+8OdH0TYZf5ZFGLdTrqgi0ybAHcLrXkM+g2JOsst99CeRUq\n" +
            "f/T4oFvuDSlLU56iWlLVE7gvDBibXfWIJ65YBHY4ueEzBC/3xOVj+dmTM2JfUSX7\n" +
            "mqD25NaDCOuN4WhJmZHC1wyipj3KYT2bLg4gasHr/LvEI+Df/DREdXtrYAqPqZYU\n" +
            "0QuubMF4n3hMqmu2wA==\n" +
            "=fMRM\n" +
            "-----END PGP MESSAGE-----";

    @Test
    public void testMessageDecryptionAndVerification() throws PGPException, IOException {
        ImplementationFactory.setFactoryImplementation(new JceImplementationFactory());
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(KLEOPATRA_SECKEY);
        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(KLEOPATRA_PUBKEY);

        ConsumerOptions options = new ConsumerOptions()
                .addDecryptionKey(secretKeys)
                .addVerificationCert(publicKeys);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(KLEOPATRA_MESSAGE.getBytes(StandardCharsets.UTF_8)))
                .withOptions(options);

        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();
    }

    @Test
    public void testEncryptAndSignMessage() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(KLEOPATRA_SECKEY);
        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(KLEOPATRA_PUBKEY);

        ProducerOptions options = ProducerOptions.signAndEncrypt(
                EncryptionOptions.encryptCommunications()
                        .addRecipient(publicKeys)
                        .overrideEncryptionAlgorithm(SymmetricKeyAlgorithm.AES_128),
                SigningOptions.get()
                        .addInlineSignature(SecretKeyRingProtector.unprotectedKeys(), secretKeys, DocumentSignatureType.BINARY_DOCUMENT)
        );

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(options);

        ByteArrayInputStream in = new ByteArrayInputStream("Hallo, Welt!\n\n".getBytes(StandardCharsets.UTF_8));
        Streams.pipeAll(in, encryptionStream);
        encryptionStream.close();
    }

    @Test
    public void testMessageInspection() throws PGPException, IOException {
        MessageInspector.EncryptionInfo info = MessageInspector.determineEncryptionInfoForMessage(
                new ByteArrayInputStream(KLEOPATRA_MESSAGE.getBytes(StandardCharsets.UTF_8)));
    }
}
