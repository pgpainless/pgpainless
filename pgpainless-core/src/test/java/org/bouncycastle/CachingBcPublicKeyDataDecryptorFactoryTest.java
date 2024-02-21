// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.bouncycastle;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.EncryptionPurpose;
import org.pgpainless.decryption_verification.CachingBcPublicKeyDataDecryptorFactory;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;

public class CachingBcPublicKeyDataDecryptorFactoryTest {

    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: C8AE 4279 5958 5F46 86A9  8B5F EC69 7C29 2BE4 44E0\n" +
            "Comment: Alice\n" +
            "\n" +
            "lFgEY1vEcxYJKwYBBAHaRw8BAQdAXOUK1uc1iBeM+mMt2nLCukXWoJd/SodrtN9S\n" +
            "U/zzwu0AAP9eePPw91KLuq6PF9jQoTRz/cW4CyiALNJpsOJIZ1rp3xOBtAVBbGlj\n" +
            "ZYiPBBMWCgBBBQJjW8RzCRDsaXwpK+RE4BYhBMiuQnlZWF9GhqmLX+xpfCkr5ETg\n" +
            "Ap4BApsBBRYCAwEABAsJCAcFFQoJCAsCmQEAAGqWAQC8oz7l8izjUis5ji+sgI+q\n" +
            "gML22VNybqmLBpzZwnNU5wEApe9fNTRbK5yAITGBscxH7o74Qe+CLI6Ni5MwzKxr\n" +
            "5AucXQRjW8RzEgorBgEEAZdVAQUBAQdAm8xk0QSvpp2ZU1KQ31E7eEZYLKpbW4JE\n" +
            "opmtMQx6AlIDAQgHAAD/XTb/qSosfkNvli3BQiUzVRAqKaU4PKAq7at6afxoYSgN\n" +
            "4Yh1BBgWCgAdBQJjW8RzAp4BApsMBRYCAwEABAsJCAcFFQoJCAsACgkQ7Gl8KSvk\n" +
            "ROB38QEA0MvDt0bjEXwFoM0E34z0MtPcG3VBYcQ+iFRIqFfEl5UA/2yZxFjoZqrs\n" +
            "AQE8TaVpXYfbc2p/GEKA9LGd9l/g0QQLnFgEY1vEcxYJKwYBBAHaRw8BAQdAyCOv\n" +
            "6hGUvHcCBSDKP3fRz+scyJ9zwMt7nFXK5A/k2YgAAQCn3Es+IhvePn3eBlcYMMr0\n" +
            "xcktrY1NJAIZPfjlUJ0J1g6LiNUEGBYKAH0FAmNbxHMCngECmwIFFgIDAQAECwkI\n" +
            "BwUVCgkIC18gBBkWCgAGBQJjW8RzAAoJECxLf7KoUc8wD18BANNpIr4E+RRVVztR\n" +
            "OVwdxSe0SRWGjkW8nHrRyghHKTuMAP9p4ZKicOYA1uZbiNNjyuJuS8xBH6Hihurb\n" +
            "gDypVgxdBQAKCRDsaXwpK+RE4EQjAP9ARZEPxKNLFkrvjoZ8nrts3qhv3VtMrU+9\n" +
            "huZnYLe1FQEAtgO6V7wutHvVARHXqPJ6lcv+SueIu+BjLFYEKuBwggs=\n" +
            "=ShJd\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    private static final String MSG = "-----BEGIN PGP MESSAGE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "hF4DJmQMTBqw3G8SAQdALkHpO0UkS/CqkwxUz74MJU3PV72ZrIL8ZcrO8ofhblkw\n" +
            "iDIhSwwGTG3tj+sG+ZVWKsmONKi7Om5seJDHQtQ8MfdCELAgwYHSt6MrgDBhuDIH\n" +
            "0kABZhq2/8qk3EGXPpc+xxs4r4g8SgHOiiHSim5NGtounXXIaF6T/hUmlorkeYf/\n" +
            "a9pCC0QXRUAr8NOcdsfbvb5V\n" +
            "=dQa8\n" +
            "-----END PGP MESSAGE-----";

    @Test
    public void test() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(KEY);
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        SubkeyIdentifier decryptionKey = new SubkeyIdentifier(secretKeys,
                info.getEncryptionSubkeys(EncryptionPurpose.ANY).get(0).getKeyID());

        PGPSecretKey secretKey = secretKeys.getSecretKey(decryptionKey.getSubkeyId());
        PGPPrivateKey privateKey = UnlockSecretKey.unlockSecretKey(secretKey, protector);
        CachingBcPublicKeyDataDecryptorFactory cachingFactory = new CachingBcPublicKeyDataDecryptorFactory(
                privateKey, decryptionKey);

        ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(MSG.getBytes());
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(ciphertextIn)
                .withOptions(ConsumerOptions.get()
                        .addCustomDecryptorFactory(cachingFactory));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();
        assertEquals("Hello, World!\n", out.toString());

        ciphertextIn = new ByteArrayInputStream(MSG.getBytes());
        decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(ciphertextIn)
                .withOptions(ConsumerOptions.get()
                        .addCustomDecryptorFactory(cachingFactory));
        out = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, out);
        decryptionStream.close();
        assertEquals("Hello, World!\n", out.toString());

        cachingFactory.clear();
    }
}
