// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.exception.MissingDecryptionMethodException;
import org.pgpainless.key.SubkeyIdentifier;

public class PreventDecryptionUsingNonEncryptionKeyTest {

    private static final String ENCRYPTION_CAPABLE_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 1E9C 0357 913E 797A E3EF  5D15 E683 CE77 5D98 8147\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "lQcYBGG3LpQBEADL6KpZqK4hVU49g7xDxalj2Nuf5rtVHmof2qcYHulPjchveUHN\n" +
            "+mHuRiyCZIZ0tlURMEvq4hQmQTxvEVkQumH5mvnpOMR0hWOM7WYZGp+X8frqzT0t\n" +
            "S2HE/PVYfN8P3W2HGarX9ihy+oqSTdmxSBTGPEHuOKeAazgL2oOPzA+dtOOVxbxC\n" +
            "YyK5r3X/Ut5rJk84OdXNRTjxqiLUneXTBnJc9HP1FpUCpBjkvgJpT9o8Ixe5OMSP\n" +
            "J+ubwscPBA5AaWXAPT0HKBo7LSgOxCIKq/QcP+YnZhsVfoUrzs4YiCUlY5U3yWt+\n" +
            "57vWxXgYJanlqnkOP+bxxkp6Yly4XnRzYGne3FWQ2y3WyZA8M66HbkmgNjuh74S5\n" +
            "RIFJ3RdPxUGzRmdl/bosxSwpqjOE26tE0373gxbQ2y5xHAFfRTrBh8RjSQBn/dUN\n" +
            "9ZO6QwOCc90B/Vlg83sNjNrkRA4E8+q8I30dX2iXUrclis5FrqZb6fJsAFA0tCv0\n" +
            "Dojk4pt3HBlrc+AUCzqnEmary5T/RchrZ8ynod9uh3P4jyOiEGS2zui66ghJ1Iqg\n" +
            "N1QVex+eyRDU4wxQQvUEX4uzmjta6VtVa1vCVi0i4N3Ntt49yi38L4V32m0duzVf\n" +
            "owyhtu3+qBbRZaeFxmJlqbjK9PASW5VtRept8cnDQU8MN3Rs8o7U0fglvwARAQAB\n" +
            "AA/+Jp1yHTaXe1KHVZjr/z2gfXsk5Fwyn8T5vfyPZj78Wgd0rL+e2Z4QC6qYZT0a\n" +
            "RWH+LBokVl/oBvKVukbjwgo54aYaq7MHaTWVi6utiRWEoaa+qNajPj+nTUHGSLKl\n" +
            "H4EEa/BNbUZ9lICj218I2czXuk7RAYcTGXu0inIgNgwj7O7Dpqpio4PYoKd8xhRw\n" +
            "cIQ5vmEdfxkb1pAstm0Mh/ERmU7l4sUbBPwEhtUA6eaoYnkW1gnNF3ss4Dt7rPlM\n" +
            "paAQF97A/uj2RryfeGRmOfUkbnEfadipSmHCYHBykSy/NBxutrjbNZY2+U4+FvyS\n" +
            "9x5YfH1Xg/PUSOb1viiNDwh0I9yQme3xybbSB8lMDjzGx4RY4+CCQSKwvaiCI7QT\n" +
            "+A8MZoPZNImQtPcyJLRnY2NKVs4OoCq6lC4H5JNbk0Yu2Vzm8j/jkIxBlD7YOIXh\n" +
            "4RXXmnbufKYUjzqioEa0A4AJDwIZKDhLmjqJ0QAXwxiRP5qSAV8ayDN8ocxMsaSb\n" +
            "Ri4nKgcSXwXV3dEMpy5nGFyf7oYatF8t89l9zGHrACeC/bYU9q4jd8lModgb+ndP\n" +
            "KCRvq2P0Yku48czKCp5v554c9kk6WyBpoJXZePbIX+1Hd71A7xBwgBSui+xRVq6o\n" +
            "Ue4GSySXJAFSkFIN2K8NZ3AsV4+SK+S0QDyRzVoEZ3fhTNkIANdsnIonVP6hsbQ4\n" +
            "+e00UHaJSxWeqlgEEc6ytf5V7VVDX59fgMdMndORh0VQgHnFbpmHj0/N5hb+wFfo\n" +
            "ryBb5EbFijruNcT1g+0TfeBduArvrvUwtnoYQpEAb/ykCVTyOf4ItESnaFTzv3Fr\n" +
            "7rdoWQo2Oei94lS1qc14fqxmMfjjZwG+aEvLwZc5UTf986UTXOvAuZuUBr5T0g4/\n" +
            "0/ilq1ZwVNmOYbyBFEIsLusSlnqYLytlRWyHY9JBQt8BG3QjixF0rBz9uKtdOjdN\n" +
            "3gOPFh/5+kmjpJ7s0M0CrfGsjaGk2jgUW1TjYQCviRrNNgZB8jKDK1pYFEQIqWYC\n" +
            "KVncr9MIAPJQzOhus0jdM7F7i0z1dSSIcQS3onLAfyGZywJFb3QCOfjLFI3StJQW\n" +
            "mKYXR7rHnvmT6b/Lk+WtMUT7TWGReG8ST4riDNAPoQeblaSMHpMKadmjME2/sjz3\n" +
            "nbm9gUfbtA8hwJP+0HPLjwx4oh6A6YaUgSKYjeTgd6T6a1Je0uTrYwsrI3Dh1lJs\n" +
            "IqgIakbFWwGBpNr+zUF2Wz7clmIb7VWd1ywoHnN48ebr6rxGp8dHecZRI2EY8se2\n" +
            "SPUd2bhrYgYlYxeFt0k35USBzBV9283Iq+c73ux5E5+yxuzZbm9/YG9rqztjlOLx\n" +
            "VZsAjuvq6Ema4sJ5CvOwNJaEbf7I6uUH/RX8kLog9P5USzWcAuWpIJUJ4Pt0juNy\n" +
            "L++sr65cgsCcdcTXTT8kIyTRnHEXDbl75IKPu9PsACEPdVRIeb6hnrPBMwKmafEq\n" +
            "0uLdnMtmmCwjc49sp69VvhXZj0cEFBgaYq7OUvWzsjlDd/IrKC+x9uJoaXb6CpMp\n" +
            "IU8KyEqwIHyqRAIz8jD9oRa/OCMTqno0fuW+Q663g2AvW/Hn/oSWiHVFaU6zJd9L\n" +
            "SPgKUIQ/jUpxLbYoC45wtui9kCvR3KbA4rI/9OQwPSUtW6fOyENkT0rwz8o76yiv\n" +
            "w22cnXrkKZZRKpfAtpXrB2f0/uLFeCUMJ5cydeCOX1jS8I4R6HOUlTGDiLQcQWxp\n" +
            "Y2UgPGFsaWNlQHBncGFpbmxlc3Mub3JnPokCTQQTAQoAQQUCYbculAmQ5oPOd12Y\n" +
            "gUcWoQQenANXkT55euPvXRXmg853XZiBRwKeAQKbBwWWAgMBAASLCQgHBZUKCQgL\n" +
            "ApkBAAAdOA/9F4H5t1QtDhtlICCAunvNXhCCALeO9sS6p3ChBcxitTVeqrjTpS/3\n" +
            "UvIDeTgswFSX4isxM27bN/ee/WdNhFIM/sNxrx6C1hdeaOskYPr6CLrzFyety4Mu\n" +
            "aeOc7CsHBUYwo7M0n4Po0z6Sc1yZHN1tKxYuyC2v8jr+QdH2DQfgl1p0xMyGXIQw\n" +
            "I5zzHK7mUUPV6Rhk0uBNzcoC2iQqLxcfxWISxGn7mBqKEnQRC15Jx30uUon3RHKh\n" +
            "O4Zo217qnAx3DgeUU9D+Bw9MByHK+rjuSCiHySfvEQNXQZroMAf8/oLrtviIm/aa\n" +
            "qoOsnIavkPJz+ScnMXeSiZkuPsBNys1S5XHBIP9BtKO6/UgVE/Lla//7j2Y42859\n" +
            "AL+v4mswCtCW4pIYTxkJjvz7eFEDWoanLutvk3wwcNCds8+vx9RYXN0T3x+l8C6F\n" +
            "AW1Mppg0oblEDw9X4wwL1pwaE29AwDLQRy0a93sqe5qePXiC3Hp3ln19ReR0+trm\n" +
            "PMvuQHTsrp+Q4WsVDKIhXONGE6Zcq2jE9w5GJDR98ASGq/b8KVjmZwslh0N6KBra\n" +
            "bFTBNvQAwKiHynOzFDgxBuZ1RqUKsuJS22ddkdDa1bcGJs2e0PucBsRbH+GJc9Xh\n" +
            "VIBeDZV/7BVRxsifv1CXYAQF0bwSWROzRV9zf8l4Nfouk2kJ/3TEpMY=\n" +
            "=JH2v\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    // same key, but with crippling self-signature with flags [C,S]
    private static final String ENCRYPTION_INCAPABLE_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 1E9C 0357 913E 797A E3EF  5D15 E683 CE77 5D98 8147\n" +
            "Comment: Alice <alice@pgpainless.org>\n" +
            "\n" +
            "lQcYBGG3LpQBEADL6KpZqK4hVU49g7xDxalj2Nuf5rtVHmof2qcYHulPjchveUHN\n" +
            "+mHuRiyCZIZ0tlURMEvq4hQmQTxvEVkQumH5mvnpOMR0hWOM7WYZGp+X8frqzT0t\n" +
            "S2HE/PVYfN8P3W2HGarX9ihy+oqSTdmxSBTGPEHuOKeAazgL2oOPzA+dtOOVxbxC\n" +
            "YyK5r3X/Ut5rJk84OdXNRTjxqiLUneXTBnJc9HP1FpUCpBjkvgJpT9o8Ixe5OMSP\n" +
            "J+ubwscPBA5AaWXAPT0HKBo7LSgOxCIKq/QcP+YnZhsVfoUrzs4YiCUlY5U3yWt+\n" +
            "57vWxXgYJanlqnkOP+bxxkp6Yly4XnRzYGne3FWQ2y3WyZA8M66HbkmgNjuh74S5\n" +
            "RIFJ3RdPxUGzRmdl/bosxSwpqjOE26tE0373gxbQ2y5xHAFfRTrBh8RjSQBn/dUN\n" +
            "9ZO6QwOCc90B/Vlg83sNjNrkRA4E8+q8I30dX2iXUrclis5FrqZb6fJsAFA0tCv0\n" +
            "Dojk4pt3HBlrc+AUCzqnEmary5T/RchrZ8ynod9uh3P4jyOiEGS2zui66ghJ1Iqg\n" +
            "N1QVex+eyRDU4wxQQvUEX4uzmjta6VtVa1vCVi0i4N3Ntt49yi38L4V32m0duzVf\n" +
            "owyhtu3+qBbRZaeFxmJlqbjK9PASW5VtRept8cnDQU8MN3Rs8o7U0fglvwARAQAB\n" +
            "AA/+Jp1yHTaXe1KHVZjr/z2gfXsk5Fwyn8T5vfyPZj78Wgd0rL+e2Z4QC6qYZT0a\n" +
            "RWH+LBokVl/oBvKVukbjwgo54aYaq7MHaTWVi6utiRWEoaa+qNajPj+nTUHGSLKl\n" +
            "H4EEa/BNbUZ9lICj218I2czXuk7RAYcTGXu0inIgNgwj7O7Dpqpio4PYoKd8xhRw\n" +
            "cIQ5vmEdfxkb1pAstm0Mh/ERmU7l4sUbBPwEhtUA6eaoYnkW1gnNF3ss4Dt7rPlM\n" +
            "paAQF97A/uj2RryfeGRmOfUkbnEfadipSmHCYHBykSy/NBxutrjbNZY2+U4+FvyS\n" +
            "9x5YfH1Xg/PUSOb1viiNDwh0I9yQme3xybbSB8lMDjzGx4RY4+CCQSKwvaiCI7QT\n" +
            "+A8MZoPZNImQtPcyJLRnY2NKVs4OoCq6lC4H5JNbk0Yu2Vzm8j/jkIxBlD7YOIXh\n" +
            "4RXXmnbufKYUjzqioEa0A4AJDwIZKDhLmjqJ0QAXwxiRP5qSAV8ayDN8ocxMsaSb\n" +
            "Ri4nKgcSXwXV3dEMpy5nGFyf7oYatF8t89l9zGHrACeC/bYU9q4jd8lModgb+ndP\n" +
            "KCRvq2P0Yku48czKCp5v554c9kk6WyBpoJXZePbIX+1Hd71A7xBwgBSui+xRVq6o\n" +
            "Ue4GSySXJAFSkFIN2K8NZ3AsV4+SK+S0QDyRzVoEZ3fhTNkIANdsnIonVP6hsbQ4\n" +
            "+e00UHaJSxWeqlgEEc6ytf5V7VVDX59fgMdMndORh0VQgHnFbpmHj0/N5hb+wFfo\n" +
            "ryBb5EbFijruNcT1g+0TfeBduArvrvUwtnoYQpEAb/ykCVTyOf4ItESnaFTzv3Fr\n" +
            "7rdoWQo2Oei94lS1qc14fqxmMfjjZwG+aEvLwZc5UTf986UTXOvAuZuUBr5T0g4/\n" +
            "0/ilq1ZwVNmOYbyBFEIsLusSlnqYLytlRWyHY9JBQt8BG3QjixF0rBz9uKtdOjdN\n" +
            "3gOPFh/5+kmjpJ7s0M0CrfGsjaGk2jgUW1TjYQCviRrNNgZB8jKDK1pYFEQIqWYC\n" +
            "KVncr9MIAPJQzOhus0jdM7F7i0z1dSSIcQS3onLAfyGZywJFb3QCOfjLFI3StJQW\n" +
            "mKYXR7rHnvmT6b/Lk+WtMUT7TWGReG8ST4riDNAPoQeblaSMHpMKadmjME2/sjz3\n" +
            "nbm9gUfbtA8hwJP+0HPLjwx4oh6A6YaUgSKYjeTgd6T6a1Je0uTrYwsrI3Dh1lJs\n" +
            "IqgIakbFWwGBpNr+zUF2Wz7clmIb7VWd1ywoHnN48ebr6rxGp8dHecZRI2EY8se2\n" +
            "SPUd2bhrYgYlYxeFt0k35USBzBV9283Iq+c73ux5E5+yxuzZbm9/YG9rqztjlOLx\n" +
            "VZsAjuvq6Ema4sJ5CvOwNJaEbf7I6uUH/RX8kLog9P5USzWcAuWpIJUJ4Pt0juNy\n" +
            "L++sr65cgsCcdcTXTT8kIyTRnHEXDbl75IKPu9PsACEPdVRIeb6hnrPBMwKmafEq\n" +
            "0uLdnMtmmCwjc49sp69VvhXZj0cEFBgaYq7OUvWzsjlDd/IrKC+x9uJoaXb6CpMp\n" +
            "IU8KyEqwIHyqRAIz8jD9oRa/OCMTqno0fuW+Q663g2AvW/Hn/oSWiHVFaU6zJd9L\n" +
            "SPgKUIQ/jUpxLbYoC45wtui9kCvR3KbA4rI/9OQwPSUtW6fOyENkT0rwz8o76yiv\n" +
            "w22cnXrkKZZRKpfAtpXrB2f0/uLFeCUMJ5cydeCOX1jS8I4R6HOUlTGDiLQcQWxp\n" +
            "Y2UgPGFsaWNlQHBncGFpbmxlc3Mub3JnPokCTQQTAQoAQQUCYbculAmQ5oPOd12Y\n" +
            "gUcWoQQenANXkT55euPvXRXmg853XZiBRwKeAQKbBwWWAgMBAASLCQgHBZUKCQgL\n" +
            "ApkBAAAdOA/9F4H5t1QtDhtlICCAunvNXhCCALeO9sS6p3ChBcxitTVeqrjTpS/3\n" +
            "UvIDeTgswFSX4isxM27bN/ee/WdNhFIM/sNxrx6C1hdeaOskYPr6CLrzFyety4Mu\n" +
            "aeOc7CsHBUYwo7M0n4Po0z6Sc1yZHN1tKxYuyC2v8jr+QdH2DQfgl1p0xMyGXIQw\n" +
            "I5zzHK7mUUPV6Rhk0uBNzcoC2iQqLxcfxWISxGn7mBqKEnQRC15Jx30uUon3RHKh\n" +
            "O4Zo217qnAx3DgeUU9D+Bw9MByHK+rjuSCiHySfvEQNXQZroMAf8/oLrtviIm/aa\n" +
            "qoOsnIavkPJz+ScnMXeSiZkuPsBNys1S5XHBIP9BtKO6/UgVE/Lla//7j2Y42859\n" +
            "AL+v4mswCtCW4pIYTxkJjvz7eFEDWoanLutvk3wwcNCds8+vx9RYXN0T3x+l8C6F\n" +
            "AW1Mppg0oblEDw9X4wwL1pwaE29AwDLQRy0a93sqe5qePXiC3Hp3ln19ReR0+trm\n" +
            "PMvuQHTsrp+Q4WsVDKIhXONGE6Zcq2jE9w5GJDR98ASGq/b8KVjmZwslh0N6KBra\n" +
            "bFTBNvQAwKiHynOzFDgxBuZ1RqUKsuJS22ddkdDa1bcGJs2e0PucBsRbH+GJc9Xh\n" +
            "VIBeDZV/7BVRxsifv1CXYAQF0bwSWROzRV9zf8l4Nfouk2kJ/3TEpMaJAkoEEwEK\n" +
            "AD4FAmG3MJUJkOaDznddmIFHFqEEHpwDV5E+eXrj710V5oPOd12YgUcCngECmwMF\n" +
            "lgIDAQAEiwkIBwWVCgkICwAAWs8QALXbuNxiLfNBZ+d+WoZVAgfDXuFtiayWr9pX\n" +
            "KGX+a1aXgrr2+e4DjjMChdyRUHiM1IH4KsHQ3ws/lrIB3Th2a25FAXwnFs03P0Xb\n" +
            "XDyl0pBH/+tzdhOugfZdA1GM16H6nT1BPzn8wk9sfQvbYk1LopioI7PVIhjjbo1g\n" +
            "rgFt6v9IEaRjfhWaOuFQ2PoYe/Nl0d2P69Wig718s7aW4cgkt5l63yu/QbBcSCTo\n" +
            "CTDqlR8Fz93E3h1v4mS6Y+yIJ1Pz8rv7HEH0o2WALMSKuPlSSBaQdimYPOlYTmxO\n" +
            "9lrdXMxTWQggiAvljzjwute5HT+1770gNuNtjbUgzyw4T/bLGTQms4dSG1FOyO4w\n" +
            "OYuyD/09bAeas99DDPR8MYj8g1xjPTwUo50kNw1p6oO8TXEItvK2xrQSc69qNbX4\n" +
            "k2tRC7ef/aGaJerzGXr8j5TPU0+qaudTF0if5oGbz2/fyg9JeLmV5yXa86o83KxR\n" +
            "EapO9b+UW46R5USUhqi9OAxN3I3SsuR60/3F1nyli4PZKGwBH3ZIjSrW4JaeUWsB\n" +
            "+f9VJKhwtshcue+FxtZVEczrlZrQxuICJTUt84gvtXz22ZGNhXTBNCMsO0UPSEj9\n" +
            "fxRW1IcRfQYnmmaJLDOMuiFynX49Ck3UzXsc4OjUGapAFGMEbL5yyJUoq8tHM+XG\n" +
            "sqSmGpGc\n" +
            "=3NqQ\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    private static final String MSG = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "hQIMA+aDznddmIFHAQ//X9ML2+fboZEJZpw/p2WD7k9SREZ24KdJtdUif98pEoFw\n" +
            "yQB5CC2s2gBENJ+2N7UV1esU/oW7Bs+RSvNKl4eIyrH/Tz3ijVd/mcGYcKOxejW8\n" +
            "4ES5BWdRj0+9/CV3AGwAKb3g3D39tbiWqh0CH+2Ayq9O8MQo4/zE+fKSjFdfPD/y\n" +
            "oLtrv9Fkh6stg+j+1QRgWG/2NIeA7/8JJlyzHvcuq0jpBUhsrVRgm0vjpyZnPl/s\n" +
            "tz3wjWBcQD1RQXFTSpgsnbB8e0FkzPGWZ5QtxKHOo8clrTQg9LUtj/S3R0iLN6sI\n" +
            "CtiTojpMRSbTOCjdFCcYR/scU+eyqDcZ096EgfBQitj4ALUYOFkILBS9M+Lh3xIz\n" +
            "rv3+z0kmRHyKn8kcmTEoqyqkZfuEMOY6gK+hD9garBJ/91tN8ul4uHax7CMwqN8/\n" +
            "yKWoATEU7ZHMe7jF6jS5pK8ET8IP2yVfZOhGZW8mcMrUMiF7LG1HepK5p7UMkmbX\n" +
            "GHkU3vEU429PL4NXDnuLufObqZBg5zSdIzo/LXtvLKXaHUv0am1JW2wQD8hAUJAt\n" +
            "Uz+NFncS+a8bbsu1wNRjAr6Rg/5VHEk/5h+zuZP8UkCQp5NID26oVvnfDkTXAZ1+\n" +
            "egh7coZ4a2IqEVBDWnkAXssxGBxVwGDr14oNC1SaABWzqPxaY0yVrpZcr30ghqPS\n" +
            "PwHcN1NCaMtJDH4ThxH5L6zHboQeX2R6x9vpWLu9FDFqEDilxHtw+7Lax4yralGC\n" +
            "q3K54WgyYD2Q2tzMXOTEwg==\n" +
            "=+Ttf\n" +
            "-----END PGP MESSAGE-----";

    @Test
    public void baseCase() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(ENCRYPTION_CAPABLE_KEY);

        ByteArrayInputStream msgIn = new ByteArrayInputStream(MSG.getBytes(StandardCharsets.UTF_8));
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(msgIn)
                .withOptions(new ConsumerOptions().addDecryptionKey(secretKeys));

        Streams.drain(decryptionStream);
        decryptionStream.close();
        OpenPgpMetadata metadata = decryptionStream.getResult();

        assertEquals(new SubkeyIdentifier(secretKeys, secretKeys.getPublicKey().getKeyID()), metadata.getDecryptionKey());
    }

    @Test
    public void nonEncryptionKeyCannotDecrypt() throws IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(ENCRYPTION_INCAPABLE_KEY);

        ByteArrayInputStream msgIn = new ByteArrayInputStream(MSG.getBytes(StandardCharsets.UTF_8));

        assertThrows(MissingDecryptionMethodException.class, () ->
            PGPainless.decryptAndOrVerify()
                .onInputStream(msgIn)
                .withOptions(new ConsumerOptions().addDecryptionKey(secretKeys)));
    }
}
