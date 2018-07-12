/*
 * Copyright 2018 Paul Schaub.
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
package org.pgpainless.pgpainless;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.Ignore;
import org.junit.Test;
import org.pgpainless.pgpainless.algorithm.KeyFlag;
import org.pgpainless.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.pgpainless.decryption_verification.PainlessResult;
import org.pgpainless.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.pgpainless.key.collection.PGPKeyRing;
import org.pgpainless.pgpainless.key.generation.KeySpec;
import org.pgpainless.pgpainless.key.generation.type.ElGamal_GENERAL;
import org.pgpainless.pgpainless.key.generation.type.RSA_GENERAL;
import org.pgpainless.pgpainless.key.generation.type.length.ElGamalLength;
import org.pgpainless.pgpainless.key.generation.type.length.RsaLength;
import org.pgpainless.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.pgpainless.util.BCUtil;

public class EncryptDecryptTest extends AbstractPGPainlessTest {

    private static final Logger LOGGER = Logger.getLogger(EncryptDecryptTest.class.getName());
    private static final Charset UTF8 = Charset.forName("UTF-8");

    private static final String testMessage = "Ah, Juliet, if the measure of thy joy\n" +
            "Be heaped like mine, and that thy skill be more\n" +
            "To blazon it, then sweeten with thy breath\n" +
            "This neighbor air, and let rich music’s tongue\n" +
            "Unfold the imagined happiness that both\n" +
            "Receive in either by this dear encounter.";

    public EncryptDecryptTest() {
        LOGGER.log(Level.INFO, "Plain Length: " + testMessage.getBytes(UTF8).length);
    }

    @Test
    public void freshKeysRsaToElGamalTest()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {
        PGPKeyRing sender = PGPainless.generateKeyRing().simpleRsaKeyRing("romeo@montague.lit", RsaLength._3072);
        PGPKeyRing recipient = PGPainless.generateKeyRing()
                .withSubKey(KeySpec.getBuilder(ElGamal_GENERAL.withLength(ElGamalLength._3072)).withKeyFlags(KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS).withDefaultAlgorithms())
                .withMasterKey(KeySpec.getBuilder(RSA_GENERAL.withLength(RsaLength._4096)).withKeyFlags(KeyFlag.SIGN_DATA, KeyFlag.CERTIFY_OTHER).withDefaultAlgorithms())
                .withPrimaryUserId("juliet@capulet.lit").withoutPassphrase().build();

        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    @Test
    public void freshKeysRsaToRsaTest()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {
        PGPKeyRing sender = PGPainless.generateKeyRing().simpleRsaKeyRing("romeo@montague.lit", RsaLength._4096);
        PGPKeyRing recipient = PGPainless.generateKeyRing().simpleRsaKeyRing("juliet@capulet.lit", RsaLength._4096);

        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    @Test
    public void freshKeysEcToEcTest() throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException {
        PGPKeyRing sender = PGPainless.generateKeyRing().simpleEcKeyRing("romeo@montague.lit");
        PGPKeyRing recipient = PGPainless.generateKeyRing().simpleEcKeyRing("juliet@capulet.lit");

        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    @Test
    public void freshKeysEcToRsaTest()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {
        PGPKeyRing sender = PGPainless.generateKeyRing().simpleEcKeyRing("romeo@montague.lit");
        PGPKeyRing recipient = PGPainless.generateKeyRing().simpleRsaKeyRing("juliet@capulet.lit", RsaLength._4096);

        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    @Test
    public void freshKeysRsaToEcTest()
            throws PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            IOException {
        PGPKeyRing sender = PGPainless.generateKeyRing().simpleRsaKeyRing("romeo@montague.lit", RsaLength._4096);
        PGPKeyRing recipient = PGPainless.generateKeyRing().simpleEcKeyRing("juliet@capulet.lit");

        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    @Ignore
    private void encryptDecryptForSecretKeyRings(PGPKeyRing sender, PGPKeyRing recipient)
            throws PGPException,
            IOException {
        PGPSecretKeyRing recipientSec = recipient.getSecretKeys();
        PGPSecretKeyRing senderSec = sender.getSecretKeys();
        PGPPublicKeyRing recipientPub = recipient.getPublicKeys();
        PGPPublicKeyRing senderPub = sender.getPublicKeys();

        SecretKeyRingProtector keyDecryptor = new UnprotectedKeysProtector();

        byte[] secretMessage = testMessage.getBytes(UTF8);

        ByteArrayOutputStream envelope = new ByteArrayOutputStream();

        EncryptionStream encryptor = PGPainless.createEncryptor()
                .onOutputStream(envelope)
                .toRecipients(recipientPub)
                .usingSecureAlgorithms()
                .signWith(keyDecryptor, senderSec)
                .noArmor();

        PainlessResult encryptionResult = encryptor.getResult();

        assertFalse(encryptionResult.getAllSignatureKeyFingerprints().isEmpty());
        for (long keyId : encryptionResult.getAllSignatureKeyFingerprints()) {
            assertTrue(BCUtil.keyRingContainsKeyWithId(senderPub, keyId));
        }

        assertFalse(encryptionResult.getRecipientKeyIds().isEmpty());
        for (long keyId : encryptionResult.getRecipientKeyIds()) {
            assertTrue(BCUtil.keyRingContainsKeyWithId(recipientPub, keyId));
        }

        assertEquals(SymmetricKeyAlgorithm.AES_256, encryptionResult.getSymmetricKeyAlgorithm());

        Streams.pipeAll(new ByteArrayInputStream(secretMessage), encryptor);
        encryptor.close();
        byte[] encryptedSecretMessage = envelope.toByteArray();

        LOGGER.log(Level.INFO, "Sender: " + PublicKeyAlgorithm.fromId(senderPub.getPublicKey().getAlgorithm()) +
        " Receiver: " + PublicKeyAlgorithm.fromId(recipientPub.getPublicKey().getAlgorithm()) +
        " Encrypted Length: " + encryptedSecretMessage.length);

        // Juliet trieth to comprehend Romeos words

        ByteArrayInputStream envelopeIn = new ByteArrayInputStream(encryptedSecretMessage);
        DecryptionStream decryptor = PGPainless.createDecryptor()
                .onInputStream(envelopeIn)
                .decryptWith(keyDecryptor, BCUtil.keyRingsToKeyRingCollection(recipientSec))
                .verifyWith(BCUtil.keyRingsToKeyRingCollection(senderPub))
                .ignoreMissingPublicKeys()
                .build();

        ByteArrayOutputStream decryptedSecretMessage = new ByteArrayOutputStream();

        Streams.pipeAll(decryptor, decryptedSecretMessage);
        decryptor.close();

        assertTrue(Arrays.equals(secretMessage, decryptedSecretMessage.toByteArray()));
        PainlessResult result = decryptor.getResult();
        assertTrue(result.containsVerifiedSignatureFrom(senderPub));
        assertTrue(result.isIntegrityProtected());
        assertTrue(result.isSigned());
        assertTrue(result.isEncrypted());
        assertTrue(result.isVerified());
    }
}
