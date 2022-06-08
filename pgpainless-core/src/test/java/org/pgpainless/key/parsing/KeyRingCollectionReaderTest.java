// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.parsing;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.util.ArmorUtils;

public class KeyRingCollectionReaderTest {

    @Test
    public void writeAndParseKeyRingCollections() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        // secret keys
        PGPSecretKeyRing alice = PGPainless.generateKeyRing().modernKeyRing("Alice <alice@pgpainless.org>");
        PGPSecretKeyRing bob = PGPainless.generateKeyRing().modernKeyRing("Bob <bob@pgpainless.org>");

        PGPSecretKeyRingCollection collection = KeyRingUtils.keyRingsToKeyRingCollection(alice, bob);
        String ascii = ArmorUtils.toAsciiArmoredString(collection);

        PGPSecretKeyRingCollection parsed = PGPainless.readKeyRing().secretKeyRingCollection(ascii);
        assertEquals(collection.size(), parsed.size());

        // public keys
        PGPPublicKeyRing pAlice = KeyRingUtils.publicKeyRingFrom(alice);
        PGPPublicKeyRing pBob = KeyRingUtils.publicKeyRingFrom(bob);

        PGPPublicKeyRingCollection pCollection = KeyRingUtils.keyRingsToKeyRingCollection(pAlice, pBob);
        ascii = ArmorUtils.toAsciiArmoredString(pCollection);

        PGPPublicKeyRingCollection pParsed = PGPainless.readKeyRing().publicKeyRingCollection(ascii);
        assertEquals(pCollection.size(), pParsed.size());
    }

    @Test
    public void parseSeparatedSecretKeyRingCollection() throws PGPException, IOException {
        String ascii = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Version: PGPainless\n" +
                "Comment: 58F2 0119 232F BBC0 B624  CCA7 7BED B6B3 2279 0657\n" +
                "Comment: Alice <alice@pgpainless.org>\n" +
                "\n" +
                "lFgEYLIldRYJKwYBBAHaRw8BAQdAv06tp4xghoxP/oDnIXuB//vH0RajTK7urjNn\n" +
                "8YlYnucAAPsFAWLAW0c70rSktFw4CbtelRvtkcsGQkJVXXekRPcrGQ5jtBxBbGlj\n" +
                "ZSA8YWxpY2VAcGdwYWlubGVzcy5vcmc+iHgEExYKACAFAmCyJXUCGwEFFgIDAQAE\n" +
                "CwkIBwUVCgkICwIeAQIZAQAKCRB77bazInkGV9XIAP9M1yDWCPta2hMoNlKj74Yo\n" +
                "kQXSI0VQT3FFq4ZIre5n9QEAxJTiMs+vhnmWChXz2RXvoqP/NdSYWZ6TLnqUy1Tz\n" +
                "JQ2cXQRgsiV1EgorBgEEAZdVAQUBAQdAMUoA28ic8ZfbCzw3z60T3kmQNWQqdTQs\n" +
                "HuxEQPj2B24DAQgHAAD/SWLvXh81Ho+6dysWNd9/qmtx0vcF1NeBsRu/Z+noe7gR\n" +
                "c4h1BBgWCgAdBQJgsiV1AhsMBRYCAwEABAsJCAcFFQoJCAsCHgEACgkQe+22syJ5\n" +
                "BleuPwEAvzGxpoCl4cRWk6t+UZdCALMdnM050sf0jruryQhg8lkBANa3i54K5Eze\n" +
                "2ah+1f5O8JLudv5t9NS1kERY2JpqVlAPnFgEYLIldRYJKwYBBAHaRw8BAQdAO0VF\n" +
                "ebLPMAYaxGl99jyLkQEJ4wNgdI1rBn3SDYnUq3kAAP4ugbF5XlRNHzxnSubS7Byf\n" +
                "bF9gnmFt8eCQWdTM0FwUvREviNUEGBYKAH0FAmCyJXUCGwIFFgIDAQAECwkIBwUV\n" +
                "CgkICwIeAV8gBBkWCgAGBQJgsiV1AAoJEOTg022wUXnBdqoA/1LjvNS65BieQ1uc\n" +
                "l0kleh+K3rm4nFTs9dE39mbAI0k1AP9uHb4ucGunvqkq9x2nuFzCZHLoaBrzgi9S\n" +
                "nGvLiHzLBgAKCRB77bazInkGV5S5AP433Ln47AHNr4u8Jo5aU5ML5f5KcxaOhQES\n" +
                "SCBQ71BYWQEAlBFEhROHvJB2NCH695/zp5z5O6tmA0rLSQxZUTvyuQg=\n" +
                "=Iwkd\n" +
                "-----END PGP PRIVATE KEY BLOCK-----\n" +
                "\n" +
                "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Version: PGPainless\n" +
                "Comment: 88DD 9483 8B3D AB5B A07B  8F77 C852 EE0C 9502 F445\n" +
                "Comment: Bob <bob@pgpainless.org>\n" +
                "\n" +
                "lFgEYLIldRYJKwYBBAHaRw8BAQdAY9AtZCfF3C8fLJ81o9qVlK4h6vgT///jGX6A\n" +
                "qg/LsF4AAQDM5uiSRDYQBNqA/DydySUNLfjMvI4Aa7ONYwLqGoOvQA+mtBhCb2Ig\n" +
                "PGJvYkBwZ3BhaW5sZXNzLm9yZz6IeAQTFgoAIAUCYLIldQIbAQUWAgMBAAQLCQgH\n" +
                "BRUKCQgLAh4BAhkBAAoJEMhS7gyVAvRFdPgBAN36fO2Oo7iXukCgzOVRxb2sE1Ay\n" +
                "+pWE+Vpt2Y4NiUrVAQCKmD0hl3SIolJf+sFpInToqT7s1P34o4hYPozEDj1IBZxd\n" +
                "BGCyJXUSCisGAQQBl1UBBQEBB0C48wzNDfxyS/vjXNDWj06C4TLiu9JizHP1SQzN\n" +
                "vs2YNQMBCAcAAP95XEFiQHLBbmpwvZiSRCt7MjXe4ODk+LPY787YyGiImBNUiHUE\n" +
                "GBYKAB0FAmCyJXUCGwwFFgIDAQAECwkIBwUVCgkICwIeAQAKCRDIUu4MlQL0RVX1\n" +
                "AP0Y1E2XEZZSBjU6a3LDY7so5h/WKyj2wFhPNlYJMPyEwAD/YwUd7K3Iu2jnSRyQ\n" +
                "YkMPpBlUiCzY1WsPrYIpsrlhsAicWARgsiV1FgkrBgEEAdpHDwEBB0D2w+nDeSk1\n" +
                "X8sGbIDc0eajB0nYaGoZ61LGjmJRXyxn/QABANmdFE//RkuC9vq150kbIXzjrm54\n" +
                "TJ/l3HLv2Vb9JV5oEhSI1QQYFgoAfQUCYLIldQIbAgUWAgMBAAQLCQgHBRUKCQgL\n" +
                "Ah4BXyAEGRYKAAYFAmCyJXUACgkQ9mL4hDfRd/aN9AEAnI2ssrPZwREpOcZsrYIe\n" +
                "xSRFKc8n8RMDizHgnSyj3ZgBAPVceQEU78wnatz/x/Jbr2hE9Pj8IJK8fT96aXti\n" +
                "CEEOAAoJEMhS7gyVAvRFw+0A/34n6qI1mJuXUNWdJd2yiGCKXLvVkwvpn2wQ5kaX\n" +
                "9/m2AQCJC+MXorN3ro7aGtlz/81rtHREZftt2YH+pAy2OWq/BQ==\n" +
                "=JB3F\n" +
                "-----END PGP PRIVATE KEY BLOCK-----";

        PGPSecretKeyRingCollection collection = PGPainless.readKeyRing().secretKeyRingCollection(ascii);
        assertEquals(2, collection.size());
        Iterator<PGPSecretKeyRing> iterator = collection.getKeyRings();
        assertEquals(new OpenPgpV4Fingerprint("58F2 0119 232F BBC0 B624  CCA7 7BED B6B3 2279 0657"),
                new OpenPgpV4Fingerprint(iterator.next()));
        assertEquals(new OpenPgpV4Fingerprint("88DD 9483 8B3D AB5B A07B  8F77 C852 EE0C 9502 F445"),
                new OpenPgpV4Fingerprint(iterator.next()));
    }

    @Test
    public void parseConcatenatedSecretKeyRingCollection() throws PGPException, IOException {
        // same key ring collection as above, but concatenated in a single armor block
        String ascii = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Version: BCPG v1.68\n" +
                "\n" +
                "lFgEYLIldRYJKwYBBAHaRw8BAQdAv06tp4xghoxP/oDnIXuB//vH0RajTK7urjNn\n" +
                "8YlYnucAAPsFAWLAW0c70rSktFw4CbtelRvtkcsGQkJVXXekRPcrGQ5jtBxBbGlj\n" +
                "ZSA8YWxpY2VAcGdwYWlubGVzcy5vcmc+iHgEExYKACAFAmCyJXUCGwEFFgIDAQAE\n" +
                "CwkIBwUVCgkICwIeAQIZAQAKCRB77bazInkGV9XIAP9M1yDWCPta2hMoNlKj74Yo\n" +
                "kQXSI0VQT3FFq4ZIre5n9QEAxJTiMs+vhnmWChXz2RXvoqP/NdSYWZ6TLnqUy1Tz\n" +
                "JQ2cXQRgsiV1EgorBgEEAZdVAQUBAQdAMUoA28ic8ZfbCzw3z60T3kmQNWQqdTQs\n" +
                "HuxEQPj2B24DAQgHAAD/SWLvXh81Ho+6dysWNd9/qmtx0vcF1NeBsRu/Z+noe7gR\n" +
                "c4h1BBgWCgAdBQJgsiV1AhsMBRYCAwEABAsJCAcFFQoJCAsCHgEACgkQe+22syJ5\n" +
                "BleuPwEAvzGxpoCl4cRWk6t+UZdCALMdnM050sf0jruryQhg8lkBANa3i54K5Eze\n" +
                "2ah+1f5O8JLudv5t9NS1kERY2JpqVlAPnFgEYLIldRYJKwYBBAHaRw8BAQdAO0VF\n" +
                "ebLPMAYaxGl99jyLkQEJ4wNgdI1rBn3SDYnUq3kAAP4ugbF5XlRNHzxnSubS7Byf\n" +
                "bF9gnmFt8eCQWdTM0FwUvREviNUEGBYKAH0FAmCyJXUCGwIFFgIDAQAECwkIBwUV\n" +
                "CgkICwIeAV8gBBkWCgAGBQJgsiV1AAoJEOTg022wUXnBdqoA/1LjvNS65BieQ1uc\n" +
                "l0kleh+K3rm4nFTs9dE39mbAI0k1AP9uHb4ucGunvqkq9x2nuFzCZHLoaBrzgi9S\n" +
                "nGvLiHzLBgAKCRB77bazInkGV5S5AP433Ln47AHNr4u8Jo5aU5ML5f5KcxaOhQES\n" +
                "SCBQ71BYWQEAlBFEhROHvJB2NCH695/zp5z5O6tmA0rLSQxZUTvyuQiUWARgsiV1\n" +
                "FgkrBgEEAdpHDwEBB0Bj0C1kJ8XcLx8snzWj2pWUriHq+BP//+MZfoCqD8uwXgAB\n" +
                "AMzm6JJENhAE2oD8PJ3JJQ0t+My8jgBrs41jAuoag69AD6a0GEJvYiA8Ym9iQHBn\n" +
                "cGFpbmxlc3Mub3JnPoh4BBMWCgAgBQJgsiV1AhsBBRYCAwEABAsJCAcFFQoJCAsC\n" +
                "HgECGQEACgkQyFLuDJUC9EV0+AEA3fp87Y6juJe6QKDM5VHFvawTUDL6lYT5Wm3Z\n" +
                "jg2JStUBAIqYPSGXdIiiUl/6wWkidOipPuzU/fijiFg+jMQOPUgFnF0EYLIldRIK\n" +
                "KwYBBAGXVQEFAQEHQLjzDM0N/HJL++Nc0NaPToLhMuK70mLMc/VJDM2+zZg1AwEI\n" +
                "BwAA/3lcQWJAcsFuanC9mJJEK3syNd7g4OT4s9jvztjIaIiYE1SIdQQYFgoAHQUC\n" +
                "YLIldQIbDAUWAgMBAAQLCQgHBRUKCQgLAh4BAAoJEMhS7gyVAvRFVfUA/RjUTZcR\n" +
                "llIGNTprcsNjuyjmH9YrKPbAWE82Vgkw/ITAAP9jBR3srci7aOdJHJBiQw+kGVSI\n" +
                "LNjVaw+tgimyuWGwCJxYBGCyJXUWCSsGAQQB2kcPAQEHQPbD6cN5KTVfywZsgNzR\n" +
                "5qMHSdhoahnrUsaOYlFfLGf9AAEA2Z0UT/9GS4L2+rXnSRshfOOubnhMn+Xccu/Z\n" +
                "Vv0lXmgSFIjVBBgWCgB9BQJgsiV1AhsCBRYCAwEABAsJCAcFFQoJCAsCHgFfIAQZ\n" +
                "FgoABgUCYLIldQAKCRD2YviEN9F39o30AQCcjayys9nBESk5xmytgh7FJEUpzyfx\n" +
                "EwOLMeCdLKPdmAEA9Vx5ARTvzCdq3P/H8luvaET0+Pwgkrx9P3ppe2IIQQ4ACgkQ\n" +
                "yFLuDJUC9EXD7QD/fifqojWYm5dQ1Z0l3bKIYIpcu9WTC+mfbBDmRpf3+bYBAIkL\n" +
                "4xeis3eujtoa2XP/zWu0dERl+23Zgf6kDLY5ar8F\n" +
                "=TTn+\n" +
                "-----END PGP PRIVATE KEY BLOCK-----";

        PGPSecretKeyRingCollection collection = PGPainless.readKeyRing().secretKeyRingCollection(ascii);
        assertEquals(2, collection.size());
        Iterator<PGPSecretKeyRing> iterator = collection.getKeyRings();
        assertEquals(new OpenPgpV4Fingerprint("58F2 0119 232F BBC0 B624  CCA7 7BED B6B3 2279 0657"),
                new OpenPgpV4Fingerprint(iterator.next()));
        assertEquals(new OpenPgpV4Fingerprint("88DD 9483 8B3D AB5B A07B  8F77 C852 EE0C 9502 F445"),
                new OpenPgpV4Fingerprint(iterator.next()));
    }
}
