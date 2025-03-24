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

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.MessageMetadata;
import org.pgpainless.exception.KeyException;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.MultiMap;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.TestAllImplementations;

public class SigningTest {

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testEncryptionAndSignatureVerification()
            throws IOException, PGPException {
        PGPainless api = PGPainless.getInstance();

        OpenPGPCertificate julietCert = TestKeys.getJulietCertificate();
        OpenPGPCertificate romeoCert = TestKeys.getRomeoCertificate();

        OpenPGPKey cryptieKey = TestKeys.getCryptieKey();
        KeyRingInfo cryptieInfo = api.inspect(cryptieKey);
        OpenPGPKey.OpenPGPSecretKey cryptieSigningKey = cryptieKey.getSecretKey(cryptieInfo.getSigningSubkeys().get(0).getKeyIdentifier());

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = api.generateMessage()
                .onOutputStream(out)
                .withOptions(ProducerOptions.signAndEncrypt(
                        EncryptionOptions.encryptDataAtRest(api)
                                .addRecipient(romeoCert)
                                .addRecipient(julietCert)
                                .addRecipient(cryptieKey.toCertificate()),
                        SigningOptions.get(api).addInlineSignature(
                                SecretKeyRingProtector.unlockSingleKeyWith(TestKeys.CRYPTIE_PASSPHRASE, cryptieSigningKey),
                                        cryptieKey, TestKeys.CRYPTIE_UID, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT),
                        api
                ).setAsciiArmor(true));

        byte[] messageBytes = "This message is signed and encrypted to Romeo and Juliet."
                .getBytes(StandardCharsets.UTF_8);
        ByteArrayInputStream message = new ByteArrayInputStream(messageBytes);

        Streams.pipeAll(message, encryptionStream);
        encryptionStream.close();

        byte[] encrypted = out.toByteArray();
        ByteArrayInputStream cryptIn = new ByteArrayInputStream(encrypted);

        OpenPGPKey romeoKey = TestKeys.getRomeoKey();
        OpenPGPKey julietKey = TestKeys.getJulietKey();

        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(cryptIn)
                .withOptions(ConsumerOptions.get(api)
                        .addDecryptionKey(romeoKey, SecretKeyRingProtector.unprotectedKeys())
                        .addDecryptionKey(julietKey, SecretKeyRingProtector.unprotectedKeys())
                        .addVerificationCert(cryptieKey.toCertificate())
                        .addVerificationCert(romeoCert)
                );

        ByteArrayOutputStream plaintextOut = new ByteArrayOutputStream();

        Streams.pipeAll(decryptionStream, plaintextOut);
        decryptionStream.close();

        MessageMetadata metadata = decryptionStream.getMetadata();
        assertTrue(metadata.isEncrypted());
        assertTrue(metadata.isVerifiedSigned());
        assertTrue(metadata.isVerifiedSignedBy(cryptieKey));
        assertFalse(metadata.isVerifiedSignedBy(julietCert));
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testSignWithInvalidUserIdFails() {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.generateKey()
                .modernKeyRing("alice", "password123");
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword("password123"));

        SigningOptions opts = SigningOptions.get(api);
        // "bob" is not a valid user-id
        assertThrows(KeyException.UnboundUserIdException.class,
                () -> opts.addInlineSignature(protector, secretKeys, "bob",
                        DocumentSignatureType.CANONICAL_TEXT_DOCUMENT));
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testSignWithRevokedUserIdFails()
            throws PGPException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.generateKey()
                .modernKeyRing("alice", "password123");
        SecretKeyRingProtector protector = SecretKeyRingProtector.unlockAnyKeyWith(
                Passphrase.fromPassword("password123"));
        secretKeys = api.modify(secretKeys)
                .revokeUserId("alice", protector)
                .done();

        final OpenPGPKey fSecretKeys = secretKeys;

        SigningOptions opts = SigningOptions.get();
        // "alice" has been revoked
        assertThrows(KeyException.UnboundUserIdException.class,
                () -> opts.addInlineSignature(protector, fSecretKeys, "alice",
                        DocumentSignatureType.CANONICAL_TEXT_DOCUMENT));
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void signWithHashAlgorithmOverride() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = TestKeys.getEmilKey();
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        SigningOptions options = SigningOptions.get(api);
        assertNull(options.getHashAlgorithmOverride());

        options.overrideHashAlgorithm(HashAlgorithm.SHA224);
        assertEquals(HashAlgorithm.SHA224, options.getHashAlgorithmOverride());

        options.addDetachedSignature(protector, secretKeys, DocumentSignatureType.BINARY_DOCUMENT);

        String data = "Hello, World!\n";
        EncryptionStream signer = api.generateMessage()
                .onOutputStream(new ByteArrayOutputStream())
                .withOptions(ProducerOptions.sign(options, api));

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
            throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.buildKey()
                .setPrimaryKey(KeySpec.getBuilder(
                        KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                        .overridePreferredHashAlgorithms())
                .addUserId("Alice")
                .build();

        SigningOptions options = SigningOptions.get(api)
                .addDetachedSignature(SecretKeyRingProtector.unprotectedKeys(), secretKeys,
                        DocumentSignatureType.BINARY_DOCUMENT);
        String data = "Hello, World!\n";
        EncryptionStream signer = api.generateMessage()
                .onOutputStream(new ByteArrayOutputStream())
                .withOptions(ProducerOptions.sign(options, api));

        Streams.pipeAll(new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)), signer);
        signer.close();
        EncryptionResult result = signer.getResult();
        MultiMap<SubkeyIdentifier, PGPSignature> sigs = result.getDetachedSignatures();
        SubkeyIdentifier signingKey = sigs.keySet().iterator().next();
        PGPSignature signature = sigs.get(signingKey).iterator().next();

        assertEquals(api.getAlgorithmPolicy().getDataSignatureHashAlgorithmPolicy().defaultHashAlgorithm().getAlgorithmId(),
                signature.getHashAlgorithm());
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void negotiateHashAlgorithmChoseFallbackIfUnacceptablePreferences()
            throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.buildKey()
                .setPrimaryKey(
                        KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                        .overridePreferredHashAlgorithms(HashAlgorithm.MD5))
                .addUserId("Alice")
                .build();

        SigningOptions options = SigningOptions.get(api)
                .addDetachedSignature(SecretKeyRingProtector.unprotectedKeys(), secretKeys,
                        DocumentSignatureType.BINARY_DOCUMENT);
        String data = "Hello, World!\n";
        EncryptionStream signer = api.generateMessage()
                .onOutputStream(new ByteArrayOutputStream())
                .withOptions(ProducerOptions.sign(options, api));

        Streams.pipeAll(new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)), signer);
        signer.close();
        EncryptionResult result = signer.getResult();
        MultiMap<SubkeyIdentifier, PGPSignature> sigs = result.getDetachedSignatures();
        SubkeyIdentifier signingKey = sigs.keySet().iterator().next();
        PGPSignature signature = sigs.get(signingKey).iterator().next();

        assertEquals(api.getAlgorithmPolicy().getDataSignatureHashAlgorithmPolicy().defaultHashAlgorithm().getAlgorithmId(),
                signature.getHashAlgorithm());
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void signingWithNonCapableKeyThrowsKeyCannotSignException() {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.buildKey()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.CERTIFY_OTHER))
                .addUserId("Alice")
                .build();

        SigningOptions options = SigningOptions.get(api);
        assertThrows(KeyException.UnacceptableSigningKeyException.class, () -> options.addDetachedSignature(
                SecretKeyRingProtector.unprotectedKeys(), secretKeys, DocumentSignatureType.BINARY_DOCUMENT));
        assertThrows(KeyException.UnacceptableSigningKeyException.class, () -> options.addInlineSignature(
                SecretKeyRingProtector.unprotectedKeys(), secretKeys, DocumentSignatureType.BINARY_DOCUMENT));
    }

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void signWithInvalidUserIdThrowsKeyValidationError() {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey secretKeys = api.buildKey()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519),
                        KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA))
                .addUserId("Alice")
                .build();

        SigningOptions options = SigningOptions.get(api);
        assertThrows(KeyException.UnboundUserIdException.class, () ->
                options.addDetachedSignature(SecretKeyRingProtector.unprotectedKeys(), secretKeys, "Bob",
                        DocumentSignatureType.BINARY_DOCUMENT));
        assertThrows(KeyException.UnboundUserIdException.class, () ->
                options.addInlineSignature(SecretKeyRingProtector.unprotectedKeys(), secretKeys, "Bob",
                        DocumentSignatureType.BINARY_DOCUMENT));
    }

}
