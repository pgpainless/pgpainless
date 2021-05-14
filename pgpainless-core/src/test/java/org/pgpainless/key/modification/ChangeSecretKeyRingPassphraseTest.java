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
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.protection.KeyRingProtectionSettings;
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.util.Passphrase;

public class ChangeSecretKeyRingPassphraseTest {

    private final PGPSecretKeyRing keyRing = PGPainless.generateKeyRing().simpleEcKeyRing("password@encryp.ted", "weakPassphrase");

    public ChangeSecretKeyRingPassphraseTest() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
    }

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestUtil#provideImplementationFactories")
    public void changePassphraseOfWholeKeyRingTest(ImplementationFactory implementationFactory) throws PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

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

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestUtil#provideImplementationFactories")
    public void changePassphraseOfWholeKeyRingToEmptyPassphrase(ImplementationFactory implementationFactory) throws PGPException, IOException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
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

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestUtil#provideImplementationFactories")
    public void changePassphraseOfSingleSubkeyToNewPassphrase(ImplementationFactory implementationFactory) throws PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

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

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestUtil#provideImplementationFactories")
    public void changePassphraseOfSingleSubkeyToEmptyPassphrase(ImplementationFactory implementationFactory) throws PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

        Iterator<PGPSecretKey> keys = keyRing.getSecretKeys();
        PGPSecretKey primaryKey = keys.next();
        PGPSecretKey subKey = keys.next();

        PGPSecretKeyRing secretKeys = PGPainless.modifyKeyRing(keyRing)
                .changeSubKeyPassphraseFromOldPassphrase(primaryKey.getKeyID(), Passphrase.fromPassword("weakPassphrase"))
                .withSecureDefaultSettings()
                .toNoPassphrase()
                .done();

        keys = secretKeys.getSecretKeys();
        primaryKey = keys.next();
        subKey = keys.next();

        extractPrivateKey(primaryKey, Passphrase.emptyPassphrase());
        extractPrivateKey(subKey, Passphrase.fromPassword("weakPassphrase"));

        final PGPSecretKey finalPrimaryKey = primaryKey;
        assertThrows(PGPException.class,
                () -> extractPrivateKey(finalPrimaryKey, Passphrase.fromPassword("weakPassphrase")),
                "Unlocking the unprotected primary key with the old passphrase must fail.");

        final PGPSecretKey finalSubKey = subKey;
        assertThrows(PGPException.class,
                () -> extractPrivateKey(finalSubKey, Passphrase.emptyPassphrase()),
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
        PGPDigestCalculatorProvider digestCalculatorProvider = new BcPGPDigestCalculatorProvider();
        if (passphrase.isEmpty() && secretKey.getKeyEncryptionAlgorithm() != SymmetricKeyAlgorithm.NULL.getAlgorithmId()) {
            throw new PGPException("Cannot unlock encrypted private key with empty passphrase.");
        } else if (!passphrase.isEmpty() && secretKey.getKeyEncryptionAlgorithm() == SymmetricKeyAlgorithm.NULL.getAlgorithmId()) {
            throw new PGPException("Cannot unlock unprotected private key with non-empty passphrase.");
        }
        PBESecretKeyDecryptor decryptor = passphrase.isEmpty() ? null : new BcPBESecretKeyDecryptorBuilder(digestCalculatorProvider)
                .build(passphrase.getChars());

        UnlockSecretKey.unlockSecretKey(secretKey, decryptor);
    }

    private void signDummyMessageWithKeysAndPassphrase(PGPSecretKeyRing keyRing, Passphrase passphrase) throws IOException, PGPException {
        String dummyMessage = "dummy";
        ByteArrayOutputStream dummy = new ByteArrayOutputStream();
        EncryptionStream stream = PGPainless.encryptAndOrSign().onOutputStream(dummy)
                .doNotEncrypt()
                .signWith(PasswordBasedSecretKeyRingProtector.forKey(keyRing, passphrase), keyRing)
                .signBinaryDocument()
                .noArmor();

        Streams.pipeAll(new ByteArrayInputStream(dummyMessage.getBytes()), stream);
        stream.close();
    }
}
