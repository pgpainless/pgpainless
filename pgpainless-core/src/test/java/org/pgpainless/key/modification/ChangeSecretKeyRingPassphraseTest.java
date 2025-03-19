// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.api.OpenPGPImplementation;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.protection.KeyRingProtectionSettings;
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.TestAllImplementations;
import org.pgpainless.util.Passphrase;

public class ChangeSecretKeyRingPassphraseTest {

    private final OpenPGPKey keyRing = PGPainless.getInstance()
            .generateKey().simpleEcKeyRing("password@encryp.ted", "weakPassphrase");

    public ChangeSecretKeyRingPassphraseTest() {
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void changePassphraseOfWholeKeyRingTest() throws PGPException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.modify(keyRing)
                .changePassphraseFromOldPassphrase(Passphrase.fromPassword("weakPassphrase"))
                .withSecureDefaultSettings()
                .toNewPassphrase(Passphrase.fromPassword("1337p455phr453"))
                .done();

        assertEquals(KeyRingProtectionSettings.secureDefaultSettings().getEncryptionAlgorithm().getAlgorithmId(),
                secretKeys.getPGPSecretKeyRing().getSecretKey().getKeyEncryptionAlgorithm());

        assertThrows(PGPException.class, () ->
                        signDummyMessageWithKeysAndPassphrase(api, secretKeys, Passphrase.emptyPassphrase()),
                "Unlocking secret key ring with empty passphrase MUST fail.");

        assertThrows(PGPException.class, () ->
                signDummyMessageWithKeysAndPassphrase(api, secretKeys, Passphrase.fromPassword("weakPassphrase")),
                "Unlocking secret key ring with old passphrase MUST fail.");

        assertDoesNotThrow(() -> signDummyMessageWithKeysAndPassphrase(api, secretKeys, Passphrase.fromPassword("1337p455phr453")),
                "Unlocking the secret key ring with the new passphrase MUST succeed.");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void changePassphraseOfWholeKeyRingToEmptyPassphrase() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();

        OpenPGPKey changedPassphraseKeyRing = api.modify(keyRing)
                .changePassphraseFromOldPassphrase(Passphrase.fromPassword("weakPassphrase"))
                .withSecureDefaultSettings()
                .toNoPassphrase()
                .done();

        assertEquals(SymmetricKeyAlgorithm.NULL.getAlgorithmId(),
                changedPassphraseKeyRing.getPGPSecretKeyRing().getSecretKey().getKeyEncryptionAlgorithm());

        signDummyMessageWithKeysAndPassphrase(api, changedPassphraseKeyRing, Passphrase.emptyPassphrase());
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void changePassphraseOfSingleSubkeyToNewPassphrase() throws PGPException {
        PGPainless api = PGPainless.getInstance();
        Iterator<PGPSecretKey> keys = keyRing.getPGPSecretKeyRing().getSecretKeys();
        PGPSecretKey primaryKey = keys.next();
        PGPSecretKey subKey = keys.next();

        extractPrivateKey(primaryKey, Passphrase.fromPassword("weakPassphrase"));
        extractPrivateKey(subKey, Passphrase.fromPassword("weakPassphrase"));

        OpenPGPKey secretKeys = api.modify(keyRing)
                .changeSubKeyPassphraseFromOldPassphrase(subKey.getPublicKey().getKeyIdentifier(),
                        Passphrase.fromPassword("weakPassphrase"))
                .withSecureDefaultSettings()
                .toNewPassphrase(Passphrase.fromPassword("subKeyPassphrase"))
                .done();

        keys = secretKeys.getPGPSecretKeyRing().getSecretKeys();
        primaryKey = keys.next();
        subKey = keys.next();

        extractPrivateKey(primaryKey, Passphrase.fromPassword("weakPassphrase"));
        extractPrivateKey(subKey, Passphrase.fromPassword("subKeyPassphrase"));

        final PGPSecretKey finalPrimaryKey = primaryKey;
        assertThrows(PGPException.class,
                () -> extractPrivateKey(finalPrimaryKey, Passphrase.fromPassword("subKeyPassphrase")),
                "Unlocking the primary key with the subkey passphrase must fail.");

        final PGPSecretKey finalSubKey = subKey;
        assertThrows(PGPException.class,
                () -> extractPrivateKey(finalSubKey, Passphrase.fromPassword("weakPassphrase")),
                "Unlocking the subkey with the primary key passphrase must fail.");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void changePassphraseOfSingleSubkeyToEmptyPassphrase() throws PGPException {
        PGPainless api = PGPainless.getInstance();
        Iterator<PGPSecretKey> keys = keyRing.getPGPSecretKeyRing().getSecretKeys();
        PGPSecretKey primaryKey = keys.next();
        PGPSecretKey subKey = keys.next();

        OpenPGPKey secretKeys = api.modify(keyRing)
                .changeSubKeyPassphraseFromOldPassphrase(subKey.getKeyIdentifier(), Passphrase.fromPassword("weakPassphrase"))
                .withSecureDefaultSettings()
                .toNoPassphrase()
                .done();

        keys = secretKeys.getPGPSecretKeyRing().getSecretKeys();
        primaryKey = keys.next();
        subKey = keys.next();

        extractPrivateKey(primaryKey, Passphrase.fromPassword("weakPassphrase"));
        extractPrivateKey(subKey, Passphrase.emptyPassphrase());

        final PGPSecretKey finalPrimaryKey = primaryKey;
        assertThrows(PGPException.class,
                () -> extractPrivateKey(finalPrimaryKey, Passphrase.emptyPassphrase()),
                "Unlocking the unprotected primary key with the old passphrase must fail.");

        final PGPSecretKey finalSubKey = subKey;
        assertThrows(PGPException.class,
                () -> extractPrivateKey(finalSubKey, Passphrase.fromPassword("weakPassphrase")),
                "Unlocking the still protected subkey with an empty passphrase must fail.");
    }

    /**
     * This method throws an PGPException if the provided passphrase cannot unlock the secret key.
     *
     * @param secretKey secret key
     * @param passphrase passphrase
     * @throws PGPException if passphrase is wrong
     */
    private void extractPrivateKey(PGPSecretKey secretKey, Passphrase passphrase) throws PGPException {
        if (passphrase.isEmpty() && secretKey.getKeyEncryptionAlgorithm() != SymmetricKeyAlgorithm.NULL.getAlgorithmId()) {
            throw new PGPException("Cannot unlock encrypted private key with empty passphrase.");
        } else if (!passphrase.isEmpty() && secretKey.getKeyEncryptionAlgorithm() == SymmetricKeyAlgorithm.NULL.getAlgorithmId()) {
            throw new PGPException("Cannot unlock unprotected private key with non-empty passphrase.");
        }
        PBESecretKeyDecryptor decryptor = passphrase.isEmpty() ?
                null :
                OpenPGPImplementation.getInstance()
                        .pbeSecretKeyDecryptorBuilderProvider()
                        .provide()
                        .build(passphrase.getChars());

        UnlockSecretKey.unlockSecretKey(secretKey, decryptor);
    }

    private void signDummyMessageWithKeysAndPassphrase(PGPainless api, OpenPGPKey key, Passphrase passphrase) throws IOException, PGPException {
        String dummyMessage = "dummy";
        ByteArrayOutputStream dummy = new ByteArrayOutputStream();
        EncryptionStream stream = api.generateMessage().onOutputStream(dummy)
                .withOptions(ProducerOptions.sign(SigningOptions.get()
                        .addInlineSignature(PasswordBasedSecretKeyRingProtector.forKey(key, passphrase),
                                key, DocumentSignatureType.BINARY_DOCUMENT)));

        Streams.pipeAll(new ByteArrayInputStream(dummyMessage.getBytes()), stream);
        stream.close();
    }
}
