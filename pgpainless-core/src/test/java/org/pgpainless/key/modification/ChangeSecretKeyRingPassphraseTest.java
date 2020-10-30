/*
 * Copyright 2020 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.key.modification;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.util.io.Streams;
import org.junit.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.key.collection.PGPKeyRing;
import org.pgpainless.key.protection.KeyRingProtectionSettings;
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector;
import org.pgpainless.util.Passphrase;

public class ChangeSecretKeyRingPassphraseTest {

    private final PGPKeyRing keyRing = PGPainless.generateKeyRing().simpleEcKeyRing("password@encryp.ted", "weakPassphrase");

    public ChangeSecretKeyRingPassphraseTest() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
    }

    @Test
    public void changePassphraseOfWholeKeyRingTest() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {

        PGPSecretKeyRing secretKeys = PGPainless.modifyKeyRing(keyRing.getSecretKeys())
                .changePassphraseFromOldPassphrase(Passphrase.fromPassword("weakPassphrase"))
                .withSecureDefaultSettings()
                .toNewPassphrase(Passphrase.fromPassword("1337p455phr453"))
                .done();

        PGPKeyRing changedPassphraseKeyRing = new PGPKeyRing(secretKeys);

        assertEquals(KeyRingProtectionSettings.secureDefaultSettings().getEncryptionAlgorithm().getAlgorithmId(),
                changedPassphraseKeyRing.getSecretKeys().getSecretKey().getKeyEncryptionAlgorithm());

        try {
            signDummyMessageWithKeysAndPassphrase(changedPassphraseKeyRing, Passphrase.emptyPassphrase());
            fail("Unlocking secret key ring with empty passphrase MUST fail.");
        } catch (PGPException e) {
            // yay
        }

        try {
            signDummyMessageWithKeysAndPassphrase(changedPassphraseKeyRing, Passphrase.fromPassword("weakPassphrase"));
            fail("Unlocking secret key ring with old passphrase MUST fail.");
        } catch (PGPException e) {
            // yay
        }

        try {
            signDummyMessageWithKeysAndPassphrase(changedPassphraseKeyRing, Passphrase.fromPassword("1337p455phr453"));
        } catch (PGPException e) {
            fail("Unlocking the secret key ring with the new passphrase MUST succeed.");
        }
    }

    @Test
    public void changePassphraseOfWholeKeyRingToEmptyPassphrase() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.modifyKeyRing(keyRing.getSecretKeys())
                .changePassphraseFromOldPassphrase(Passphrase.fromPassword("weakPassphrase"))
                .withSecureDefaultSettings()
                .toNoPassphrase()
                .done();

        PGPKeyRing changedPassphraseKeyRing = new PGPKeyRing(secretKeys);

        assertEquals(SymmetricKeyAlgorithm.NULL.getAlgorithmId(),
                changedPassphraseKeyRing.getSecretKeys().getSecretKey().getKeyEncryptionAlgorithm());

        signDummyMessageWithKeysAndPassphrase(changedPassphraseKeyRing, Passphrase.emptyPassphrase());
    }

    @Test
    public void changePassphraseOfSingleSubkeyToNewPassphrase() throws PGPException {

        Iterator<PGPSecretKey> keys = keyRing.getSecretKeys().getSecretKeys();
        PGPSecretKey primaryKey = keys.next();
        PGPSecretKey subKey = keys.next();

        extractPrivateKey(primaryKey, Passphrase.fromPassword("weakPassphrase"));
        extractPrivateKey(subKey, Passphrase.fromPassword("weakPassphrase"));

        PGPSecretKeyRing secretKeys = PGPainless.modifyKeyRing(keyRing.getSecretKeys())
                .changeSubKeyPassphraseFromOldPassphrase(subKey.getPublicKey().getKeyID(),
                        Passphrase.fromPassword("weakPassphrase"))
                .withSecureDefaultSettings()
                .toNewPassphrase(Passphrase.fromPassword("subKeyPassphrase"))
                .done();

        keys = secretKeys.getSecretKeys();
        primaryKey = keys.next();
        subKey = keys.next();

        extractPrivateKey(primaryKey, Passphrase.fromPassword("weakPassphrase"));
        extractPrivateKey(subKey, Passphrase.fromPassword("subKeyPassphrase"));

        try {
            extractPrivateKey(primaryKey, Passphrase.fromPassword("subKeyPassphrase"));
            fail("Unlocking the primary key with the subkey passphrase must fail.");
        } catch (PGPException e) {
            // yay
        }

        try {
            extractPrivateKey(subKey, Passphrase.fromPassword("weakPassphrase"));
            fail("Unlocking the subkey with the primary key passphrase must fail.");
        } catch (PGPException e) {
            // yay
        }
    }

    @Test
    public void changePassphraseOfSingleSubkeyToEmptyPassphrase() throws PGPException {
        Iterator<PGPSecretKey> keys = keyRing.getSecretKeys().getSecretKeys();
        PGPSecretKey primaryKey = keys.next();
        PGPSecretKey subKey = keys.next();

        PGPSecretKeyRing secretKeys = PGPainless.modifyKeyRing(keyRing.getSecretKeys())
                .changeSubKeyPassphraseFromOldPassphrase(primaryKey.getKeyID(), Passphrase.fromPassword("weakPassphrase"))
                .withSecureDefaultSettings()
                .toNoPassphrase()
                .done();

        keys = secretKeys.getSecretKeys();
        primaryKey = keys.next();
        subKey = keys.next();

        extractPrivateKey(primaryKey, Passphrase.emptyPassphrase());
        extractPrivateKey(subKey, Passphrase.fromPassword("weakPassphrase"));

        try {
            extractPrivateKey(primaryKey, Passphrase.fromPassword("weakPassphrase"));
            fail("Unlocking the unprotected primary key with the old passphrase must fail.");
        } catch (PGPException e) {
            // yay
        }

        try {
            extractPrivateKey(subKey, Passphrase.emptyPassphrase());
            fail("Unlocking the still protected subkey with an empty passphrase must fail.");
        } catch (PGPException e) {
            // yay
        }

    }

    /**
     * This method throws an PGPException if the provided passphrase cannot unlock the secret key.
     *
     * @param secretKey secret key
     * @param passphrase passphrase
     * @throws PGPException if passphrase is wrong
     */
    private void extractPrivateKey(PGPSecretKey secretKey, Passphrase passphrase) throws PGPException {
        PGPDigestCalculatorProvider digestCalculatorProvider = new BcPGPDigestCalculatorProvider();
        if (passphrase.isEmpty() && secretKey.getKeyEncryptionAlgorithm() != SymmetricKeyAlgorithm.NULL.getAlgorithmId()) {
            throw new PGPException("Cannot unlock encrypted private key with empty passphrase.");
        } else if (!passphrase.isEmpty() && secretKey.getKeyEncryptionAlgorithm() == SymmetricKeyAlgorithm.NULL.getAlgorithmId()) {
            throw new PGPException("Cannot unlock unprotected private key with non-empty passphrase.");
        }
        PBESecretKeyDecryptor decryptor = passphrase.isEmpty() ? null : new BcPBESecretKeyDecryptorBuilder(digestCalculatorProvider)
                .build(passphrase.getChars());

        secretKey.extractPrivateKey(decryptor);
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
