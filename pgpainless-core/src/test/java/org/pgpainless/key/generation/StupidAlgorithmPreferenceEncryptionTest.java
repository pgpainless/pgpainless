// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionResult;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.rsa.RsaLength;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class StupidAlgorithmPreferenceEncryptionTest {

    @Test
    public void testPreventUnencryptedAlgorithmPreferenceDuringKeyGeneration() {
        KeySpecBuilder specBuilder = KeySpec.getBuilder(KeyType.RSA(RsaLength._4096), KeyFlag.CERTIFY_OTHER);
        assertThrows(IllegalArgumentException.class, () ->
                specBuilder.overridePreferredSymmetricKeyAlgorithms(
                        SymmetricKeyAlgorithm.AES_256, SymmetricKeyAlgorithm.AES_192,
                        SymmetricKeyAlgorithm.AES_128, SymmetricKeyAlgorithm.NULL));
    }

    // RSA key with symmetric algorithm preference "NULL" (unencrypted).
    private static final String STUPID_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 6CA6 C4F3 CF01 CAC9 C954  0BD6 5BDA 78ED C479 A8E9\n" +
            "Comment: This is Stupid\n" +
            "\n" +
            "lQcYBGLRTLUBEADg2W4x7HgoBDJS7qYCqheyY/J/SNKJ7AvPTTd8V7S9rxZ6kZlo\n" +
            "556q1+KJA+/jWJ3LFvuNCyTW/utQxxLYylDFTaI4KJ5MWWLtvlph+VjolI/+u8B6\n" +
            "qSeZl72uXiEFW8vnQfBliXOyWCudLHh4cRj/DgxEbL3Cm9FXH0/XYRKweSPRhOkX\n" +
            "Mh/veiTe7a6RcwGOi0DNcRth5g4MggspgHQmNcHq2XGeOOpQUeJXPjNsKZIShI3M\n" +
            "nYVz78xqVNdn2xJjUq6H/bREV5fDn73xWcNCxyNSl7rvk7kcYNKf977MgoVPSUlN\n" +
            "sOZ19/YFMU+Bexqsdvzf/txn9BzgUhwufpeUrSFLIwiy+X7fY+pURR4G4hpeg1eD\n" +
            "xAl5FFRAtDqk7C6XlaP9j0qxZmbYrTfqbIS5+u0iJ93nO3CIWE87pnzhZH9E00jM\n" +
            "H6e6IV4op8pcG+6mvg1NPeJg6uwpUwzmbmnvF85WtQ4QVmOSPjFigZPSkNf/4qNm\n" +
            "05IP8mCGNd7Xl+J4I6JGVNjhB9Vk9/3wbVrtjD00EAkTgiSmjT2lt5TiE6rVjQJ4\n" +
            "krvte70UNH4yuoGOap1w993HmcYSObe4Q3JBhLA7F9lnprAi+kL8gc0SFEAk5tOX\n" +
            "H4Cqnk4ml01IamGOzXa01p//1NrxyMVYefD1+JT6X4wogUzvwLJqTehICQARAQAB\n" +
            "AA/+MRiI7TG7EtHHw0AE07QcNIGKY6yc/Cykb4FmyinEd16Rw/Wiz7szdA5rkotf\n" +
            "h/7DhaLhDm0OgDttWlf9j4StmkdXUnfcCMPDzDGyPo5ZkX9O6cpJPv9MfEcbzcUT\n" +
            "5L2kijxlp2YZ8yk5bLpXG8VmNdr1ZsNvs9yeGy3lGxxBHnN1FLy2wK/bNUkwX9T6\n" +
            "NxwrjNpvLeyyk+/NxYFnuoon0mgOjZ8pJek7kIowp+gXBlkVYiG7bKBAkY4czmL0\n" +
            "HeNB4podLeiBwiJ2KuroaJi3AA/HcLNcyA8zbjTeCLvp13Hwdd2EuggUalHYUE3y\n" +
            "FE2zB1F76dUWf0RYQcrsCGLv6cf3uu2yxNttUlzKrni1lcwvA6ZyauUuLg8E9chi\n" +
            "oT5zkpxnEdR1eVRBZQDWGXQuXpDiDxAu/bMyW3uhLRLKhP2D0+m0TeCBsIwU5Fdz\n" +
            "nn13IjY/zsUUQT2rxCSnU4ooFXkzT2FTVAKbX+0/raFS6JJsQI4wJPoFMm5QycwR\n" +
            "kWRiKUzcDTLKXtyISwZvPaQnomuExdKJFaW/+FEtYgqyfFYHR7Nmo1e7HxkEjmkm\n" +
            "IxYMOApNXAkwBR8nMdUzchN0C6fogCUk+gj41eU4s6yzHjiRvmt85/N8T+34+MUk\n" +
            "xRCtytNEseTvfs4vFPKksz9QK8vUpjIhXdxVrr/Asl4At5kIAOTZ9Psq/jQydg9u\n" +
            "4A4X5JHTPszw9GKo43u020PPxgOe6nuYlF0sWBzjPoKvkkN4mEOYi5SRmmnChrZV\n" +
            "r82QEsjhQToxE0I4PYnhXJgNlNn4aNCK4a3oD1rqQQC4DE/hDtogFQIovqiLT3cS\n" +
            "kdcLcnUs2G7QYEdXWPXowdclxQQwlpCjd9VO2UNdNITmkloT5nZ0WLik323kEF7z\n" +
            "3cZXj/uRnPa/Y5whFa1AA7cPIDht5B+BXw+TEzeTkmjxO/GEVMdJl8unUIyt+G5N\n" +
            "FKsFG86nezLT9m77Yu3rrA/z+uRa0vVot63is8Spiuc6hkRBFlC6xsBVnC/OZnrf\n" +
            "dG+Fk2MIAPuF7x82gAdX+M1u1kvrAR1Ze0fy+CYkvUokA+q0C7hsc1Gdh2bemBWf\n" +
            "Dt+pr3Td2xn2YfCb8lSF6+o8p8qe4kkq2eNLd1/k5SSA1SSrP2J97ByhWdX6tNnf\n" +
            "mT37izMdS2mRVjBcVR1zdhwaXN3m5+bqUpggrmuz9lwemnUPfSn5shO0YomQp9z1\n" +
            "I1dkuIAF+InCZH7NyNWAoVLJ0Bk7MPQTZNVn/iEsfDWcPQEpumF1aY8+cpvUqeEZ\n" +
            "r8nPsZ1r2P2WAjC7o9uYEL+47AAFMxD3Ps8GHR9cG9GSVn88NetNQ22Vm2GafRYi\n" +
            "Y+Fny5cfxWTLUSldQuehwmLsJZXp0KMIAKL7XxabHx5B0h5leCdB6y82fz3TTQV2\n" +
            "khwodAQ06itzG0fhMAF0O87KFDOq9p+Bx4n6MzHunEL2rJuF+KLOAMnyHRVQ40a1\n" +
            "V/8JnsjCViceicLKWVQgxlBIFFAlHRoHrAc2g1Sup96zt5kmojNhEtFeJNQkQcpa\n" +
            "x7atpyrlD2j8oMdr0dJluQcSGhS3/Y/LLCWtNbijykGDfBMQn0tHEgESwVx5muIj\n" +
            "Hn5yfRIA0/MBg9Py9H4r52Ab6XBs7mDZSrmOoXcCzQY3RgykP01Q8/ipIo7C/Yi6\n" +
            "aun8QzBLvykeRFfEu1SM523jLMn66CLqKDQR+8IxDgORFwXhwSfGVVl2iLQOVGhp\n" +
            "cyBpcyBTdHVwaWSJAkgEEwEKADwFAmLRTLUJEFvaeO3EeajpFiEEbKbE888BysnJ\n" +
            "VAvWW9p47cR5qOkCngECmw8FFgIDAQACCwACFQoCmQEAABRQEACNK0cNjEUcOEJh\n" +
            "cfG2Hjs6oWClklV9eSNcVQU7S3wT+xr+WwV5S8TJaZtLlvsnp9ZaS4u5/1zY1+ll\n" +
            "Ahzclg5BU4jihs4N+aBWRf2XovnH8cEHEneu9pXs0Sunj/DVCfHRuRe5Z8Vng9SN\n" +
            "rofxSfvL9PD5zTwWLHJUZD+yTxI9hmj3G37OTVQbmhtjXGZ0IRaa5fjO9FTwUske\n" +
            "fhB/7TIwrSDByhj857uF1j4d1i3WjSvps3FuVBuUYc+RLEm8QgkGWGu/QHjvkmUe\n" +
            "fM1onDXL8JHYX0ULZ1s/sH5oTUXVH6ZQOdFIQeENeYSDZN5P5bDzshO/Dwn5t2f8\n" +
            "yuV9nxdlK6TGUByyOINkoMf6U7IJfPmdThcqmUoPjUav2ha4uNOhJEL3a1R9RrDk\n" +
            "q+kiKrT65QTuVl5pE5JjjEuVuGuMjlWnh2aieG9z8sIXqela/1LlOe0MboVTTVv9\n" +
            "FvR4kz3GGfqSYHTu229R7QEthd9y3NMrPeW8i2ZCZMch3FMhym5sDiSw1okKC4rE\n" +
            "hhNECnwdCw9DGdqEPgh8RWpjVKQNdCk1gjH+/EnCjlMl7pRcdzkBbKE0TuZTP3ww\n" +
            "V0q86MQmyWkFO9fQQ9LakERO1OzP0fMob7mce8ZdP7qENAqAYRQLJR4iHPSjcRFz\n" +
            "WFv0UlYdnSNZfY0vroIMxnM1w4XJVg==\n" +
            "=4plS\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    @Test
    public void testEncryptionIsNotUnencrypted() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey stupidKey = api.readKey().parseKey(STUPID_KEY);
        OpenPGPCertificate certificate = stupidKey.toCertificate();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = api.generateMessage()
                .onOutputStream(out)
                .withOptions(ProducerOptions.encrypt(
                        EncryptionOptions.get(api).addRecipient(certificate)
                ));

        encryptionStream.write("Hello".getBytes(StandardCharsets.UTF_8));
        encryptionStream.close();

        EncryptionResult metadata = encryptionStream.getResult();
        assertTrue(metadata.isEncryptedFor(certificate));
        assertEquals(api.getAlgorithmPolicy().getSymmetricKeyEncryptionAlgorithmPolicy().getDefaultSymmetricKeyAlgorithm(),
                metadata.getEncryptionAlgorithm());
    }
}
