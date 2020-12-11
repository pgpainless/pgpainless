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
package org.pgpainless.encryption_signing;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Set;
import java.util.logging.Logger;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.elgamal.ElGamal_GENERAL;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.elgamal.ElGamalLength;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.util.BCUtil;

public class EncryptDecryptTest {

    private static final Logger LOGGER = Logger.getLogger(EncryptDecryptTest.class.getName());
    // Don't use StandardCharsets.UTF_8 because of Android API level.
    private static final Charset UTF8 = Charset.forName("UTF-8");

    private static final String testMessage =
            "Ah, Juliet, if the measure of thy joy\n" +
            "Be heaped like mine, and that thy skill be more\n" +
            "To blazon it, then sweeten with thy breath\n" +
            "This neighbor air, and let rich music’s tongue\n" +
            "Unfold the imagined happiness that both\n" +
            "Receive in either by this dear encounter.";

    @SuppressWarnings("deprecation")
    @Test
    public void freshKeysRsaToElGamalTest()
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException {
        PGPSecretKeyRing sender = PGPainless.generateKeyRing().simpleRsaKeyRing("romeo@montague.lit", RsaLength._3072);
        PGPSecretKeyRing recipient = PGPainless.generateKeyRing()
                .withSubKey(KeySpec.getBuilder(ElGamal_GENERAL.withLength(ElGamalLength._3072)).withKeyFlags(KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS).withDefaultAlgorithms())
                .withMasterKey(KeySpec.getBuilder(KeyType.RSA(RsaLength._4096)).withKeyFlags(KeyFlag.SIGN_DATA, KeyFlag.CERTIFY_OTHER).withDefaultAlgorithms())
                .withPrimaryUserId("juliet@capulet.lit").withoutPassphrase().build();

        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    @Test
    public void freshKeysRsaToRsaTest()
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException {
        PGPSecretKeyRing sender = PGPainless.generateKeyRing().simpleRsaKeyRing("romeo@montague.lit", RsaLength._3072);
        PGPSecretKeyRing recipient = PGPainless.generateKeyRing().simpleRsaKeyRing("juliet@capulet.lit", RsaLength._3072);

        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    @Test
    public void freshKeysEcToEcTest()
            throws IOException, PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        PGPSecretKeyRing sender = PGPainless.generateKeyRing().simpleEcKeyRing("romeo@montague.lit");
        PGPSecretKeyRing recipient = PGPainless.generateKeyRing().simpleEcKeyRing("juliet@capulet.lit");

        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    @Test
    public void freshKeysEcToRsaTest()
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException {
        PGPSecretKeyRing sender = PGPainless.generateKeyRing().simpleEcKeyRing("romeo@montague.lit");
        PGPSecretKeyRing recipient = PGPainless.generateKeyRing().simpleRsaKeyRing("juliet@capulet.lit", RsaLength._3072);

        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    @Test
    public void freshKeysRsaToEcTest()
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException {
        PGPSecretKeyRing sender = PGPainless.generateKeyRing().simpleRsaKeyRing("romeo@montague.lit", RsaLength._3072);
        PGPSecretKeyRing recipient = PGPainless.generateKeyRing().simpleEcKeyRing("juliet@capulet.lit");

        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    @Test
    public void existingRsaKeysTest() throws IOException, PGPException {
        PGPSecretKeyRing sender = TestKeys.getJulietSecretKeyRing();
        PGPSecretKeyRing recipient = TestKeys.getRomeoSecretKeyRing();

        encryptDecryptForSecretKeyRings(sender, recipient);
    }

    private void encryptDecryptForSecretKeyRings(PGPSecretKeyRing senderSec, PGPSecretKeyRing recipientSec)
            throws PGPException, IOException {

        PGPPublicKeyRing recipientPub = KeyRingUtils.publicKeyRingFrom(recipientSec);
        PGPPublicKeyRing senderPub = KeyRingUtils.publicKeyRingFrom(senderSec);

        SecretKeyRingProtector keyDecryptor = new UnprotectedKeysProtector();

        byte[] secretMessage = testMessage.getBytes(UTF8);

        ByteArrayOutputStream envelope = new ByteArrayOutputStream();

        EncryptionStream encryptor = PGPainless.encryptAndOrSign()
                .onOutputStream(envelope)
                .toRecipients(recipientPub)
                .usingSecureAlgorithms()
                .signWith(keyDecryptor, senderSec)
                .noArmor();

        Streams.pipeAll(new ByteArrayInputStream(secretMessage), encryptor);
        encryptor.close();
        byte[] encryptedSecretMessage = envelope.toByteArray();

        OpenPgpMetadata encryptionResult = encryptor.getResult();

        assertFalse(encryptionResult.getSignatures().isEmpty());
        for (OpenPgpV4Fingerprint fingerprint : encryptionResult.getVerifiedSignatures().keySet()) {
            assertTrue(BCUtil.keyRingContainsKeyWithId(senderPub, fingerprint.getKeyId()));
        }

        assertFalse(encryptionResult.getRecipientKeyIds().isEmpty());
        for (long keyId : encryptionResult.getRecipientKeyIds()) {
            assertTrue(BCUtil.keyRingContainsKeyWithId(recipientPub, keyId));
        }

        assertEquals(SymmetricKeyAlgorithm.AES_256, encryptionResult.getSymmetricKeyAlgorithm());

        // Juliet trieth to comprehend Romeos words

        ByteArrayInputStream envelopeIn = new ByteArrayInputStream(encryptedSecretMessage);
        DecryptionStream decryptor = PGPainless.decryptAndOrVerify()
                .onInputStream(envelopeIn)
                .decryptWith(keyDecryptor, BCUtil.keyRingsToKeyRingCollection(recipientSec))
                .verifyWith(BCUtil.keyRingsToKeyRingCollection(senderPub))
                .ignoreMissingPublicKeys()
                .build();

        ByteArrayOutputStream decryptedSecretMessage = new ByteArrayOutputStream();

        Streams.pipeAll(decryptor, decryptedSecretMessage);
        decryptor.close();

        assertArrayEquals(secretMessage, decryptedSecretMessage.toByteArray());
        OpenPgpMetadata result = decryptor.getResult();
        assertTrue(result.containsVerifiedSignatureFrom(senderPub));
        assertTrue(result.isIntegrityProtected());
        assertTrue(result.isSigned());
        assertTrue(result.isEncrypted());
        assertTrue(result.isVerified());
    }

    @Test
    public void testDetachedSignatureCreationAndVerification() throws IOException, PGPException {
        PGPSecretKeyRing signingKeys = TestKeys.getJulietSecretKeyRing();
        SecretKeyRingProtector keyRingProtector = new UnprotectedKeysProtector();
        byte[] data = testMessage.getBytes();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
        ByteArrayOutputStream dummyOut = new ByteArrayOutputStream();
        EncryptionStream signer = PGPainless.encryptAndOrSign().onOutputStream(dummyOut)
                .doNotEncrypt()
                .createDetachedSignature()
                .signWith(keyRingProtector, signingKeys)
                .noArmor();
        Streams.pipeAll(inputStream, signer);
        signer.close();
        OpenPgpMetadata metadata = signer.getResult();

        Set<PGPSignature> signatureSet = metadata.getSignatures();
        ByteArrayOutputStream sigOut = new ByteArrayOutputStream();
        ArmoredOutputStream armorOut = new ArmoredOutputStream(sigOut);
        signatureSet.iterator().next().encode(armorOut);
        armorOut.close();
        String armorSig = sigOut.toString();

        // CHECKSTYLE:OFF
        System.out.println(armorSig);
        // CHECKSTYLE:ON

        inputStream = new ByteArrayInputStream(testMessage.getBytes());
        DecryptionStream verifier = PGPainless.decryptAndOrVerify().onInputStream(inputStream)
                .doNotDecrypt()
                .verifyDetachedSignature(new ByteArrayInputStream(armorSig.getBytes()))
                .verifyWith(Collections.singleton(KeyRingUtils.publicKeyRingFrom(signingKeys)))
                .ignoreMissingPublicKeys()
                .build();
        dummyOut = new ByteArrayOutputStream();
        Streams.pipeAll(verifier, dummyOut);
        verifier.close();

        metadata = verifier.getResult();
        assertFalse(metadata.getVerifiedSignatures().isEmpty());
    }

    @Test
    public void testOnePassSignatureCreationAndVerification() throws IOException, PGPException {
        PGPSecretKeyRing signingKeys = TestKeys.getJulietSecretKeyRing();
        SecretKeyRingProtector keyRingProtector = new UnprotectedKeysProtector();
        byte[] data = testMessage.getBytes();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
        ByteArrayOutputStream signOut = new ByteArrayOutputStream();
        EncryptionStream signer = PGPainless.encryptAndOrSign().onOutputStream(signOut)
                .doNotEncrypt()
                .signWith(keyRingProtector, signingKeys)
                .asciiArmor();
        Streams.pipeAll(inputStream, signer);
        signer.close();

        // CHECKSTYLE:OFF
        System.out.println(signOut.toString());
        // CHECKSTYLE:ON

        inputStream = new ByteArrayInputStream(signOut.toByteArray());
        DecryptionStream verifier = PGPainless.decryptAndOrVerify().onInputStream(inputStream)
                .doNotDecrypt()
                .verifyWith(Collections.singleton(KeyRingUtils.publicKeyRingFrom(signingKeys)))
                .ignoreMissingPublicKeys()
                .build();
        signOut = new ByteArrayOutputStream();
        Streams.pipeAll(verifier, signOut);
        verifier.close();

        OpenPgpMetadata metadata = verifier.getResult();
        assertFalse(metadata.getVerifiedSignatures().isEmpty());
    }
}
