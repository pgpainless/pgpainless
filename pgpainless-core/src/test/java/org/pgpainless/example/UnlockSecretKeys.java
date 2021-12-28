// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.example;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.CachingSecretKeyRingProtector;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.Passphrase;

/**
 * {@link PGPSecretKey PGPSecretKeys} are often password protected to prevent unauthorized access.
 * To perform certain actions with secret keys, such as creating signatures or decrypting encrypted messages,
 * the secret key needs to be unlocked to access the underlying {@link org.bouncycastle.openpgp.PGPPrivateKey}.
 *
 * Providing the required {@link org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor}/{@link org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor}
 * is a task that needs to be performed by the {@link SecretKeyRingProtector}.
 * There are different implementations available that implement this interface.
 *
 * Below are some examples of how to use these implementations in different scenarios.
 */
public class UnlockSecretKeys {

    /**
     * This example demonstrates how to create a {@link SecretKeyRingProtector} for unprotected secret keys.
     */
    @Test
    public void unlockUnprotectedKeys() throws PGPException, IOException {
        PGPSecretKeyRing unprotectedKey = TestKeys.getJulietSecretKeyRing();
        // This protector will only unlock unprotected keys
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();


        assertProtectorUnlocksAllSecretKeys(unprotectedKey, protector);
    }

    /**
     * This example demonstrates how to create a {@link SecretKeyRingProtector} using a single passphrase to unlock
     * all secret subkeys of a key.
     */
    @Test
    public void unlockWholeKeyWithSamePassphrase() throws PGPException, IOException {
        PGPSecretKeyRing secretKey = TestKeys.getCryptieSecretKeyRing();
        Passphrase passphrase = TestKeys.CRYPTIE_PASSPHRASE;

        // Unlock all subkeys in the secret key with the same passphrase
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAnyKeyWith(passphrase);

        assertProtectorUnlocksAllSecretKeys(secretKey, protector);
    }

    /**
     * This example demonstrates how to create a {@link SecretKeyRingProtector} that uses different
     * passphrases per subkey to unlock the secret keys.
     */
    @Test
    public void unlockWithPerSubkeyPassphrases() throws PGPException, IOException {
        String pgpPrivateKeyBlock = "" +
                "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
                "Version: PGPainless\n" +
                "Comment: 4F28 5D16 A201 21BB 5B89  E76E 5D71 171E 059A 1D2F\n" +
                "Comment: alice@pgpainless.org\n" +
                "\n" +
                "lIYEYNc8xhYJKwYBBAHaRw8BAQdAQiDSNqkU4b4TmdacOxi9mfw06pI23NNiTj/C\n" +
                "K1P+Q0/+CQMCm+6zb2ORC8BgHltvucr4KKx7QZdO5jIDWDZe1DjeS2JsJXoqOMeK\n" +
                "yjxB8aVoSZTmsAm1KMbeDWcqtsltgm+DipRUyWFxeYOoj+CugJ42GbQUYWxpY2VA\n" +
                "cGdwYWlubGVzcy5vcmeIeAQTFgoAIAUCYNc8xgIbAQUWAgMBAAQLCQgHBRUKCQgL\n" +
                "Ah4BAhkBAAoJEF1xFx4Fmh0viTEBAJmfpCJsVi7BzMh2iP6ecWZSRYtgqAhKjGTT\n" +
                "4i9IKgIUAP47SbJr4qexi3jWj9W9ng//+CKEQ857Up6iSR6u+3poApyLBGDXPMYS\n" +
                "CisGAQQBl1UBBQEBB0BUfOJMRcgWdPeyEz2kL79JfhckuDRAwZJyGd8mcFBofQMB\n" +
                "CAf+CQMCKdEpNMEpflBguXamH33Vhx2tr3iYleiWI0VfhPrQledNzJ1uCHFH5q+k\n" +
                "UnALeSCLJXIekPl3q1ux9C2MQkD/X4+mHh+fE4gSd1G5nd3oh4h1BBgWCgAdBQJg\n" +
                "1zzGAhsMBRYCAwEABAsJCAcFFQoJCAsCHgEACgkQXXEXHgWaHS/8DgD/Qnpe5g6C\n" +
                "WHeXvgg06PJR7HRPkpE5NSnqEWP9X0tPe2EBAIdTiDozZ7HL6NVI89MnLBkw+524\n" +
                "y5YzlNpQn4Al3tMCnIYEYNc8xhYJKwYBBAHaRw8BAQdAXdTUv2F0XGfi4qFnIPrL\n" +
                "YbOpEZIWYjGVf5Ggbs9OBrb+CQMClCGIqeO7yJlgR9z490pJUD4al/ATofqGPPqx\n" +
                "VsTz4gl1IkkWKQn7GJv2AYn09jZgnWm2a7u16cS6HZLJjRl2XvMzMQp3dRsOPHTP\n" +
                "nulJ7YjVBBgWCgB9BQJg1zzGAhsCBRYCAwEABAsJCAcFFQoJCAsCHgFfIAQZFgoA\n" +
                "BgUCYNc8xgAKCRD2BAJwjnXZQQLiAQCJGx9PF5ywwE93nMu8nZrhgDtl/eiCsryM\n" +
                "qjDfY5XyCgEAim9m50QU9I9gAzBgLeH2NSJhlHYZZ2LKsRE02tGvXQMACgkQXXEX\n" +
                "HgWaHS806AD+KUmSoKja11wJqCMVhYSU2IMGdGYEwa7Dqpbhyzu/LtAA/jmF10Ss\n" +
                "UPPI6jsYqxEHzRGex8t971atnDAjvDiS31YN\n" +
                "=fTmB\n" +
                "-----END PGP PRIVATE KEY BLOCK-----";
        PGPSecretKeyRing secretKey = PGPainless.readKeyRing().secretKeyRing(pgpPrivateKeyBlock);

        CachingSecretKeyRingProtector protector = SecretKeyRingProtector.defaultSecretKeyRingProtector(null);
        // Add passphrases for subkeys via public key
        protector.addPassphrase(secretKey.getPublicKey(),
                Passphrase.fromPassword("pr1maryK3y"));
        // or via subkey-id
        protector.addPassphrase(3907509425258753406L,
                Passphrase.fromPassword("f1rs7subk3y"));
        // or via fingerprint
        protector.addPassphrase(new OpenPgpV4Fingerprint("DD8E1195E4B1720E7FB10EF7F60402708E75D941"),
                Passphrase.fromPassword("s3c0ndsubk3y"));


        assertProtectorUnlocksAllSecretKeys(secretKey, protector);
    }

    private void assertProtectorUnlocksAllSecretKeys(PGPSecretKeyRing secretKey, SecretKeyRingProtector protector)
            throws PGPException {
        for (PGPSecretKey key : secretKey) {
            UnlockSecretKey.unlockSecretKey(key, protector);
        }
    }
}
