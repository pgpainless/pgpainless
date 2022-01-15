// SPDX-FileCopyrightText: 2018 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;

public class RespectPreferredSymmetricAlgorithmDuringEncryptionTest {

    @Test
    public void algorithmPreferencesAreRespectedDependingOnEncryptionTarget() throws IOException, PGPException {
        // Key has AES256, AES192, AES128 as primary user-ids sym algo prefs,
        // and AES128 as secondary user-id prefs
        String key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "Version: PGPainless\n" +
                "Comment: 7E13 2E9C EAE8 7E7B AD6C  5329 94CE B847 EEFB 044B\n" +
                "Comment: Bob Babbage <bob@openpgp.example>\n" +
                "\n" +
                "mDMEYeIhnhYJKwYBBAHaRw8BAQdAfs9SkOSEyAQmvwLwwUPCp3Qiw2t4rm+e7n8t\n" +
                "oVjAmle0IUJvYiBCYWJiYWdlIDxib2JAb3BlbnBncC5leGFtcGxlPoiPBBMWCgBB\n" +
                "BQJh4iGeCZCUzrhH7vsESxahBH4TLpzq6H57rWxTKZTOuEfu+wRLAp4BApsBBZYC\n" +
                "AwEABIsJCAcFlQoJCAsCmQEAAKK/AP4lCifuXpZIUR4PrenGBZFtoZpB5s1i/YrB\n" +
                "cnCuodQX9wEAyENhlXNYopWdgBZ9g4E1Y0cJfpwCwWhx0DeATmrSzAO0H0JvYmJ5\n" +
                "MTI4IDxib2JieUBhZXMxMjguZXhhbXBsZT6IigQTFgoAPAUCYeIhngmQlM64R+77\n" +
                "BEsWoQR+Ey6c6uh+e61sUymUzrhH7vsESwKeAQKbAQWWAgMBAAKLBwWVCgkICwAA\n" +
                "y0wBAIhAEpQgJRizHitPx3WUpIYbKq3R5jAO34NnlmTzNVj6AP9aWHPsW5r7HuQh\n" +
                "xJz+8zdCOuAxKv6tvHthSWJ64VWDDrg4BGHiIZ4SCisGAQQBl1UBBQEBB0CEIv13\n" +
                "/qTXR0wiUG5DVZCWh/KLKrF5TemUfYXA/kBTOAMBCAeIdQQYFgoAHQUCYeIhngKe\n" +
                "AQKbDAWWAgMBAASLCQgHBZUKCQgLAAoJEJTOuEfu+wRLwC4A/0/VDPPDE6kT/8C3\n" +
                "9d8ekZkQE38o2nC58E62AjM5O2x6AQDMd0gcoKIxPi9uRi3nVsNS233a3MxFEjpe\n" +
                "qqgyBnqxBLgzBGHiIZ4WCSsGAQQB2kcPAQEHQP7IGdT9moutwtys4A/ndkWJVWn/\n" +
                "zkoOn3cSad1bP8y8iNUEGBYKAH0FAmHiIZ4CngECmwIFlgIDAQAEiwkIBwWVCgkI\n" +
                "C18gBBkWCgAGBQJh4iGeAAoJENcuZc0+RPVgrucBAI+IzpplBIpySOIyzHJdjeFt\n" +
                "ikwTBOY3OTriY2Z62Ec6AQDhVxO7LZuH3mTCklj4HelfMrhlqUlnYr7qCIjzI5BY\n" +
                "BwAKCRCUzrhH7vsES4snAP4qzlEbaHpN7ZPomCOHD7J2+CHlyTtsRP45XWVCqNH1\n" +
                "jAEAmzz5Lu67k97AzArpoGHgYh492w5BfdApV8BCaTW4AgI=\n" +
                "=XwJQ\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";

        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(key);


        // Encrypt without specifying user-id
        // PGPainless now inspects the primary user-ids signature to get sym alg prefs (AES256, AES192, AES128)
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign().onOutputStream(out)
                .withOptions(
                        ProducerOptions.encrypt(new EncryptionOptions()
                                .addRecipient(publicKeys) // no user-id passed
                        ));

        encryptionStream.close();
        assertEquals(SymmetricKeyAlgorithm.AES_256, encryptionStream.getResult().getEncryptionAlgorithm());

        // Encrypt to the primary user-id
        // PGPainless should extract algorithm preferences from the latest user-id sig in this case (AES-256, AES-192, AES-128)
        out = new ByteArrayOutputStream();
        encryptionStream = PGPainless.encryptAndOrSign().onOutputStream(out)
                .withOptions(
                        ProducerOptions.encrypt(new EncryptionOptions()
                                .addRecipient(publicKeys, "Bob Babbage <bob@openpgp.example>")
                        ));

        encryptionStream.close();
        assertEquals(SymmetricKeyAlgorithm.AES_256, encryptionStream.getResult().getEncryptionAlgorithm());

        // Encrypt to the secondary user-id
        // PGPainless extracts algorithm preferences from secondary user-id sig, in this case AES-128
        out = new ByteArrayOutputStream();
        encryptionStream = PGPainless.encryptAndOrSign().onOutputStream(out)
                .withOptions(
                        ProducerOptions.encrypt(new EncryptionOptions()
                                .addRecipient(publicKeys, "Bobby128 <bobby@aes128.example>")
                        ));

        encryptionStream.close();
        assertEquals(SymmetricKeyAlgorithm.AES_128, encryptionStream.getResult().getEncryptionAlgorithm());
    }
}
