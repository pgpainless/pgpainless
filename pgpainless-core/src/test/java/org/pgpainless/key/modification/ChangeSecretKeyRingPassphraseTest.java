package org.pgpainless.key.modification;

import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.key.collection.PGPKeyRing;
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector;
import org.pgpainless.util.Passphrase;

public class ChangeSecretKeyRingPassphraseTest {

    @Test
    public void changePassphraseTest() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {
        PGPKeyRing keyRing = PGPainless.generateKeyRing().simpleEcKeyRing("password@encryp.ted", "weakPassphrase");
        PGPSecretKeyRing secretKeys = PGPainless.modifyKeyRing(keyRing.getSecretKeys())
                .changePassphraseFromOldPassphrase(Passphrase.fromPassword("weakPassphrase"))
                .withSecureDefaultSettings()
                .toNewPassphrase(Passphrase.fromPassword("1337p455phr453"))
                .done();

        keyRing = new PGPKeyRing(secretKeys);

        try {
            signDummyMessageWithKeysAndPassphrase(keyRing, Passphrase.fromPassword("weakPassphrase"));
            fail("Unlocking secret key ring with old passphrase MUST fail.");
        } catch (PGPException e) {
            // yay
        }

        try {
            signDummyMessageWithKeysAndPassphrase(keyRing, Passphrase.fromPassword("1337p455phr453"));
        } catch (PGPException e) {
            fail("Unlocking the secret key ring with the new passphrase MUST succeed.");
        }
    }

    private void signDummyMessageWithKeysAndPassphrase(PGPKeyRing keyRing, Passphrase passphrase) throws IOException, PGPException {
        String dummyMessage = "dummy";
            ByteArrayOutputStream dummy = new ByteArrayOutputStream();
            EncryptionStream stream = PGPainless.createEncryptor().onOutputStream(dummy)
                    .doNotEncrypt()
                    .signWith(PasswordBasedSecretKeyRingProtector.forKey(keyRing.getSecretKeys(), passphrase), keyRing.getSecretKeys())
                    .noArmor();

            Streams.pipeAll(new ByteArrayInputStream(dummyMessage.getBytes()), stream);
            stream.close();
    }
}
