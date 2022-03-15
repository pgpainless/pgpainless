// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.exception.KeyException;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.util.MultiMap;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.TestAllImplementations;

public class SigningTest {

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testEncryptionAndSignatureVerification()
            throws IOException, PGPException {

        PGPPublicKeyRing julietKeys = TestKeys.getJulietPublicKeyRing();
        PGPPublicKeyRing romeoKeys = TestKeys.getRomeoPublicKeyRing();

        PGPSecretKeyRing cryptieKeys = TestKeys.getCryptieSecretKeyRing();
        KeyRingInfo cryptieInfo = new KeyRingInfo(cryptieKeys);
        PGPSecretKey cryptieSigningKey = cryptieKeys.getSecretKey(cryptieInfo.getSigningSubkeys().get(0).getKeyID());

        PGPPublicKeyRingCollection keys = new PGPPublicKeyRingCollection(Arrays.asList(julietKeys, romeoKeys));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(ProducerOptions.signAndEncrypt(
                        EncryptionOptions.encryptDataAtRest()
                                .addRecipients(keys)
                                .addRecipient(KeyRingUtils.publicKeyRingFrom(cryptieKeys)),
                        new SigningOptions().addInlineSignature(
                                SecretKeyRingProtector.unlockSingleKeyWith(TestKeys.CRYPTIE_PASSPHRASE, cryptieSigningKey),
                                        cryptieKeys, TestKeys.CRYPTIE_UID, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT)
                ).setAsciiArmor(true));

        byte[] messageBytes = "This message is signed and encrypted to Romeo and Juliet."
                .getBytes(StandardCharsets.UTF_8);
        ByteArrayInputStream message = new ByteArrayInputStream(messageBytes);

        Streams.pipeAll(message, encryptionStream);
        encryptionStream.close();

        byte[] encrypted = out.toByteArray();
        ByteArrayInputStream cryptIn = new ByteArrayInputStream(encrypted);

        PGPSecretKeyRing romeoSecret = TestKeys.getRomeoSecretKeyRing();
        PGPSecretKeyRing julietSecret = TestKeys.getJulietSecretKeyRing();

        PGPSecretKeyRingCollection secretKeys = new PGPSecretKeyRingCollection(
                Arrays.asList(romeoSecret, julietSecret));
        PGPPublicKeyRingCollection verificationKeys = new PGPPublicKeyRingCollection(
                Arrays.asList(KeyRingUtils.publicKeyRingFrom(cryptieKeys), romeoKeys));

        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(cryptIn)
                .withOptions(new ConsumerOptions()
                        .addDecryptionKeys(secretKeys, SecretKeyRingProtector.unprotectedKeys())
                        .addVerificationCerts(verificationKeys)
                );

        ByteArrayOutputStream plaintextOut = new ByteArrayOutputStream();

        Streams.pipeAll(decryptionStream, plaintextOut);
        decryptionStream.close();

        OpenPgpMetadata metadata = decryptionStream.getResult();
        assertTrue(metadata.isEncrypted());
        assertTrue(metadata.isSigned());
        assertTrue(metadata.isVerified());
        assertTrue(metadata.containsVerifiedSignatureFrom(KeyRingUtils.publicKeyRingFrom(cryptieKeys)));
        assertFalse(metadata.containsVerifiedSignatureFrom(julietKeys));
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testSignWithInvalidUserIdFails()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("alice", "password123");
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword("password123"));

        SigningOptions opts = new SigningOptions();
        // "bob" is not a valid user-id
        assertThrows(KeyException.UnboundUserIdException.class,
                () -> opts.addInlineSignature(protector, secretKeys, "bob",
                        DocumentSignatureType.CANONICAL_TEXT_DOCUMENT));
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testSignWithRevokedUserIdFails()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .modernKeyRing("alice", "password123");
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAnyKeyWith(
                Passphrase.fromPassword("password123"));
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .revokeUserId("alice", protector)
                .done();

        final PGPSecretKeyRing fSecretKeys = secretKeys;

        SigningOptions opts = new SigningOptions();
        // "alice" has been revoked
        assertThrows(KeyException.UnboundUserIdException.class,
                () -> opts.addInlineSignature(protector, fSecretKeys, "alice",
                        DocumentSignatureType.CANONICAL_TEXT_DOCUMENT));
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void signWithHashAlgorithmOverride() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        SigningOptions options = new SigningOptions();
        assertNull(options.getHashAlgorithmOverride());

        options.overrideHashAlgorithm(HashAlgorithm.SHA224);
        assertEquals(HashAlgorithm.SHA224, options.getHashAlgorithmOverride());

        options.addDetachedSignature(protector, secretKeys, DocumentSignatureType.BINARY_DOCUMENT);

        String data = "Hello, World!\n";
        EncryptionStream signer = PGPainless.encryptAndOrSign()
                .onOutputStream(new ByteArrayOutputStream())
                .withOptions(ProducerOptions.sign(options));

        Streams.pipeAll(new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)), signer);
        signer.close();
        EncryptionResult result = signer.getResult();

        MultiMap<SubkeyIdentifier, PGPSignature> sigs = result.getDetachedSignatures();
        assertEquals(1, sigs.size());
        SubkeyIdentifier signingKey = sigs.keySet().iterator().next();
        assertEquals(1, sigs.get(signingKey).size());
        PGPSignature signature = sigs.get(signingKey).iterator().next();

        assertEquals(HashAlgorithm.SHA224.getAlgorithmId(), signature.getHashAlgorithm());
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void negotiateHashAlgorithmChoseFallbackIfEmptyPreferences()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(
                        KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                        .overridePreferredHashAlgorithms())
                .addUserId("Alice")
                .build();

        SigningOptions options = new SigningOptions()
                .addDetachedSignature(SecretKeyRingProtector.unprotectedKeys(), secretKeys,
                        DocumentSignatureType.BINARY_DOCUMENT);
        String data = "Hello, World!\n";
        EncryptionStream signer = PGPainless.encryptAndOrSign()
                .onOutputStream(new ByteArrayOutputStream())
                .withOptions(ProducerOptions.sign(options));

        Streams.pipeAll(new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)), signer);
        signer.close();
        EncryptionResult result = signer.getResult();
        MultiMap<SubkeyIdentifier, PGPSignature> sigs = result.getDetachedSignatures();
        SubkeyIdentifier signingKey = sigs.keySet().iterator().next();
        PGPSignature signature = sigs.get(signingKey).iterator().next();

        assertEquals(PGPainless.getPolicy().getSignatureHashAlgorithmPolicy().defaultHashAlgorithm().getAlgorithmId(),
                signature.getHashAlgorithm());
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void negotiateHashAlgorithmChoseFallbackIfUnacceptablePreferences()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.buildKeyRing()
                .setPrimaryKey(
                        KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                        .overridePreferredHashAlgorithms(HashAlgorithm.MD5))
                .addUserId("Alice")
                .build();

        SigningOptions options = new SigningOptions()
                .addDetachedSignature(SecretKeyRingProtector.unprotectedKeys(), secretKeys,
                        DocumentSignatureType.BINARY_DOCUMENT);
        String data = "Hello, World!\n";
        EncryptionStream signer = PGPainless.encryptAndOrSign()
                .onOutputStream(new ByteArrayOutputStream())
                .withOptions(ProducerOptions.sign(options));

        Streams.pipeAll(new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)), signer);
        signer.close();
        EncryptionResult result = signer.getResult();
        MultiMap<SubkeyIdentifier, PGPSignature> sigs = result.getDetachedSignatures();
        SubkeyIdentifier signingKey = sigs.keySet().iterator().next();
        PGPSignature signature = sigs.get(signingKey).iterator().next();

        assertEquals(PGPainless.getPolicy().getSignatureHashAlgorithmPolicy().defaultHashAlgorithm().getAlgorithmId(),
                signature.getHashAlgorithm());
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void signingWithNonCapableKeyThrowsKeyCannotSignException()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.CERTIFY_OTHER))
                .addUserId("Alice")
                .build();

        SigningOptions options = new SigningOptions();
        assertThrows(KeyException.UnacceptableSigningKeyException.class, () -> options.addDetachedSignature(
                SecretKeyRingProtector.unprotectedKeys(), secretKeys, DocumentSignatureType.BINARY_DOCUMENT));
        assertThrows(KeyException.UnacceptableSigningKeyException.class, () -> options.addInlineSignature(
                SecretKeyRingProtector.unprotectedKeys(), secretKeys, DocumentSignatureType.BINARY_DOCUMENT));
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void signWithInvalidUserIdThrowsKeyValidationError()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519),
                        KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA))
                .addUserId("Alice")
                .build();

        SigningOptions options = new SigningOptions();
        assertThrows(KeyException.UnboundUserIdException.class, () ->
                options.addDetachedSignature(SecretKeyRingProtector.unprotectedKeys(), secretKeys, "Bob",
                        DocumentSignatureType.BINARY_DOCUMENT));
        assertThrows(KeyException.UnboundUserIdException.class, () ->
                options.addInlineSignature(SecretKeyRingProtector.unprotectedKeys(), secretKeys, "Bob",
                        DocumentSignatureType.BINARY_DOCUMENT));
    }

}
