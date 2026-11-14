// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPSignature;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.SignatureVerification;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.generation.type.xdh_legacy.XDHLegacySpec;
import org.pgpainless.key.protection.SecretKeyRingProtector;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class MultiSigningSubkeyTest {

    private static PGPainless api;
    private static OpenPGPKey signingKey;
    private static OpenPGPCertificate signingCert;
    private static OpenPGPCertificate.OpenPGPComponentKey primaryKey;
    private static OpenPGPCertificate.OpenPGPComponentKey signingKey1;
    private static OpenPGPCertificate.OpenPGPComponentKey signingKey2;
    private static SecretKeyRingProtector protector;

    @BeforeAll
    public static void generateKey() {
        api = PGPainless.getInstance();
        signingKey = api.buildKey()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA))
                .addSubkey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.SIGN_DATA))
                .addSubkey(KeySpec.getBuilder(KeyType.RSA(RsaLength._3072), KeyFlag.SIGN_DATA))
                .addSubkey(KeySpec.getBuilder(KeyType.XDH_LEGACY(XDHLegacySpec._X25519), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE))
                .addUserId("Alice <alice@pgpainless.org>")
                .build();
        signingCert = signingKey.toCertificate();
        Iterator<OpenPGPCertificate.OpenPGPComponentKey> signingSubkeys = api.inspect(signingKey).getSigningSubkeys().listIterator();
        primaryKey = signingSubkeys.next();
        signingKey1 = signingSubkeys.next();
        signingKey2 = signingSubkeys.next();
        protector = SecretKeyRingProtector.unprotectedKeys();
    }

    @Test
    public void detachedSignWithAllSubkeys() throws PGPException, IOException {
        ByteArrayInputStream dataIn = new ByteArrayInputStream("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream signingStream = api.generateMessage()
                .onOutputStream(out)
                .withOptions(ProducerOptions.sign(SigningOptions.get(api)
                        .addDetachedSignature(protector, signingKey, DocumentSignatureType.BINARY_DOCUMENT)));
        Streams.pipeAll(dataIn, signingStream);
        signingStream.close();

        OpenPGPSignatureSet<OpenPGPSignature.OpenPGPDocumentSignature> sigs =
                signingStream.getResult().getDetachedDocumentSignatures();
        assertFalse(sigs.getSignaturesBy(primaryKey).isEmpty());
        assertFalse(sigs.getSignaturesBy(signingKey1).isEmpty());
        assertFalse(sigs.getSignaturesBy(signingKey2).isEmpty());
    }

    @Test
    public void detachedSignWithSingleSubkey() throws PGPException, IOException {
        ByteArrayInputStream dataIn = new ByteArrayInputStream("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream signingStream = api.generateMessage()
                .onOutputStream(out)
                .withOptions(ProducerOptions.sign(
                        SigningOptions.get(api).addDetachedSignature(protector, signingKey.getSecretKey(signingKey1))));
        Streams.pipeAll(dataIn, signingStream);
        signingStream.close();

        OpenPGPSignatureSet<OpenPGPSignature.OpenPGPDocumentSignature> sigs = signingStream.getResult().getDetachedDocumentSignatures();
        assertFalse(sigs.getSignaturesBy(signingKey1).isEmpty());
    }

    @Test
    public void inlineSignWithAllSubkeys() throws PGPException, IOException {
        ByteArrayInputStream dataIn = new ByteArrayInputStream("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream signingStream = api.generateMessage()
                .onOutputStream(out)
                .withOptions(ProducerOptions.sign(SigningOptions.get(api).addInlineSignature(protector, signingKey, DocumentSignatureType.BINARY_DOCUMENT)));
        Streams.pipeAll(dataIn, signingStream);
        signingStream.close();

        ByteArrayInputStream signedIn = new ByteArrayInputStream(out.toByteArray());
        DecryptionStream verificationStream = api.processMessage().onInputStream(signedIn)
                .withOptions(ConsumerOptions.get(api).addVerificationCert(signingCert));
        Streams.drain(verificationStream);
        verificationStream.close();

        List<SignatureVerification> sigs = verificationStream.getMetadata().getVerifiedSignatures();
        List<OpenPGPCertificate.OpenPGPComponentKey> sigKeys = sigs.stream()
                .map(s -> s.getDocumentSignature().getIssuer())
                .collect(Collectors.toList());

        assertTrue(sigKeys.contains(primaryKey));
        assertTrue(sigKeys.contains(signingKey1));
        assertTrue(sigKeys.contains(signingKey2));
    }

    @Test
    public void inlineSignWithSingleSubkey() throws PGPException, IOException {
        ByteArrayInputStream dataIn = new ByteArrayInputStream("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream signingStream = api.generateMessage()
                .onOutputStream(out)
                .withOptions(ProducerOptions.sign(SigningOptions.get(api)
                        .addInlineSignature(protector, signingKey.getSecretKey(signingKey1))));
        Streams.pipeAll(dataIn, signingStream);
        signingStream.close();

        ByteArrayInputStream signedIn = new ByteArrayInputStream(out.toByteArray());
        DecryptionStream verificationStream = api.processMessage().onInputStream(signedIn)
                .withOptions(ConsumerOptions.get(api).addVerificationCert(signingCert));
        Streams.drain(verificationStream);
        verificationStream.close();

        List<SignatureVerification> sigs = verificationStream.getMetadata().getVerifiedSignatures();
        assertEquals(1, sigs.size());
        assertEquals(signingKey1, sigs.get(0).getDocumentSignature().getIssuer());
    }

}
