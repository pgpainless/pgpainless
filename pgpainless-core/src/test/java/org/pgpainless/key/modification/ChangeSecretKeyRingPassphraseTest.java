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
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
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
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.protection.KeyRingProtectionSettings;
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.TestAllImplementations;
import org.pgpainless.util.Passphrase;

public class ChangeSecretKeyRingPassphraseTest {

    private final PGPSecretKeyRing keyRing = PGPainless.generateKeyRing().simpleEcKeyRing("password@encryp.ted", "weakPassphrase");

    public ChangeSecretKeyRingPassphraseTest() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void changePassphraseOfWholeKeyRingTest() throws PGPException {

        PGPSecretKeyRing secretKeys = PGPainless.modifyKeyRing(keyRing)
                .changePassphraseFromOldPassphrase(Passphrase.fromPassword("weakPassphrase"))
                .withSecureDefaultSettings()
                .toNewPassphrase(Passphrase.fromPassword("1337p455phr453"))
                .done();

        PGPSecretKeyRing changedPassphraseKeyRing = secretKeys;

        assertEquals(KeyRingProtectionSettings.secureDefaultSettings().getEncryptionAlgorithm().getAlgorithmId(),
                changedPassphraseKeyRing.getSecretKey().getKeyEncryptionAlgorithm());

        assertThrows(PGPException.class, () ->
                        signDummyMessageWithKeysAndPassphrase(changedPassphraseKeyRing, Passphrase.emptyPassphrase()),
                "Unlocking secret key ring with empty passphrase MUST fail.");

        assertThrows(PGPException.class, () ->
                signDummyMessageWithKeysAndPassphrase(changedPassphraseKeyRing, Passphrase.fromPassword("weakPassphrase")),
                "Unlocking secret key ring with old passphrase MUST fail.");

        assertDoesNotThrow(() -> signDummyMessageWithKeysAndPassphrase(changedPassphraseKeyRing, Passphrase.fromPassword("1337p455phr453")),
                "Unlocking the secret key ring with the new passphrase MUST succeed.");
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void changePassphraseOfWholeKeyRingToEmptyPassphrase() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.modifyKeyRing(keyRing)
                .changePassphraseFromOldPassphrase(Passphrase.fromPassword("weakPassphrase"))
                .withSecureDefaultSettings()
                .toNoPassphrase()
                .done();

        PGPSecretKeyRing changedPassphraseKeyRing = secretKeys;

        assertEquals(SymmetricKeyAlgorithm.NULL.getAlgorithmId(),
                changedPassphraseKeyRing.getSecretKey().getKeyEncryptionAlgorithm());

        signDummyMessageWithKeysAndPassphrase(changedPassphraseKeyRing, Passphrase.emptyPassphrase());
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void changePassphraseOfSingleSubkeyToNewPassphrase() throws PGPException {

        Iterator<PGPSecretKey> keys = keyRing.getSecretKeys();
        PGPSecretKey primaryKey = keys.next();
        PGPSecretKey subKey = keys.next();

        extractPrivateKey(primaryKey, Passphrase.fromPassword("weakPassphrase"));
        extractPrivateKey(subKey, Passphrase.fromPassword("weakPassphrase"));

        PGPSecretKeyRing secretKeys = PGPainless.modifyKeyRing(keyRing)
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

        Iterator<PGPSecretKey> keys = keyRing.getSecretKeys();
        PGPSecretKey primaryKey = keys.next();
        PGPSecretKey subKey = keys.next();

        PGPSecretKeyRing secretKeys = PGPainless.modifyKeyRing(keyRing)
                .changeSubKeyPassphraseFromOldPassphrase(subKey.getKeyID(), Passphrase.fromPassword("weakPassphrase"))
                .withSecureDefaultSettings()
                .toNoPassphrase()
                .done();

        keys = secretKeys.getSecretKeys();
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
        PBESecretKeyDecryptor decryptor = passphrase.isEmpty() ? null : ImplementationFactory.getInstance().getPBESecretKeyDecryptor(passphrase);

        UnlockSecretKey.unlockSecretKey(secretKey, decryptor);
    }

    private void signDummyMessageWithKeysAndPassphrase(PGPSecretKeyRing keyRing, Passphrase passphrase) throws IOException, PGPException {
        String dummyMessage = "dummy";
        ByteArrayOutputStream dummy = new ByteArrayOutputStream();
        EncryptionStream stream = PGPainless.encryptAndOrSign().onOutputStream(dummy)
                .withOptions(ProducerOptions.sign(SigningOptions.get()
                        .addInlineSignature(PasswordBasedSecretKeyRingProtector.forKey(keyRing, passphrase),
                                keyRing, DocumentSignatureType.BINARY_DOCUMENT)));

        Streams.pipeAll(new ByteArrayInputStream(dummyMessage.getBytes()), stream);
        stream.close();
    }
}
