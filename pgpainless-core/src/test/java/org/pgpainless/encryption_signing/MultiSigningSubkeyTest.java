// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.SignatureVerification;
import org.pgpainless.key.SubkeyIdentifier;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.generation.type.xdh.XDHSpec;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.util.MultiMap;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class MultiSigningSubkeyTest {

    private static PGPSecretKeyRing signingKey;
    private static PGPPublicKeyRing signingCert;
    private static SubkeyIdentifier primaryKey;
    private static SubkeyIdentifier signingKey1;
    private static SubkeyIdentifier signingKey2;
    private static SecretKeyRingProtector protector;

    @BeforeAll
    public static void generateKey() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        signingKey = PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA))
                .addSubkey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.SIGN_DATA))
                .addSubkey(KeySpec.getBuilder(KeyType.RSA(RsaLength._3072), KeyFlag.SIGN_DATA))
                .addSubkey(KeySpec.getBuilder(KeyType.XDH(XDHSpec._X25519), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE))
                .addUserId("Alice <alice@pgpainless.org>")
                .build();
        signingCert = PGPainless.extractCertificate(signingKey);
        Iterator<PGPPublicKey> signingSubkeys = PGPainless.inspectKeyRing(signingKey).getSigningSubkeys().listIterator();
        primaryKey = new SubkeyIdentifier(signingKey, signingSubkeys.next().getKeyID());
        signingKey1 = new SubkeyIdentifier(signingKey, signingSubkeys.next().getKeyID());
        signingKey2 = new SubkeyIdentifier(signingKey, signingSubkeys.next().getKeyID());
        protector = SecretKeyRingProtector.unprotectedKeys();
    }

    @Test
    public void detachedSignWithAllSubkeys() throws PGPException, IOException {
        ByteArrayInputStream dataIn = new ByteArrayInputStream("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream signingStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(ProducerOptions.sign(SigningOptions.get().addDetachedSignature(protector, signingKey, DocumentSignatureType.BINARY_DOCUMENT)));
        Streams.pipeAll(dataIn, signingStream);
        signingStream.close();

        MultiMap<SubkeyIdentifier, PGPSignature> sigs = signingStream.getResult().getDetachedSignatures();
        assertTrue(sigs.containsKey(primaryKey));
        assertTrue(sigs.containsKey(signingKey1));
        assertTrue(sigs.containsKey(signingKey2));
    }

    @Test
    public void detachedSignWithSingleSubkey() throws PGPException, IOException {
        ByteArrayInputStream dataIn = new ByteArrayInputStream("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream signingStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(ProducerOptions.sign(SigningOptions.get().addDetachedSignature(protector, signingKey, signingKey1.getKeyId())));
        Streams.pipeAll(dataIn, signingStream);
        signingStream.close();

        MultiMap<SubkeyIdentifier, PGPSignature> sigs = signingStream.getResult().getDetachedSignatures();
        assertEquals(1, sigs.flatten().size());
        assertTrue(sigs.containsKey(signingKey1));
    }

    @Test
    public void inlineSignWithAllSubkeys() throws PGPException, IOException {
        ByteArrayInputStream dataIn = new ByteArrayInputStream("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream signingStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(ProducerOptions.sign(SigningOptions.get().addInlineSignature(protector, signingKey, DocumentSignatureType.BINARY_DOCUMENT)));
        Streams.pipeAll(dataIn, signingStream);
        signingStream.close();

        ByteArrayInputStream signedIn = new ByteArrayInputStream(out.toByteArray());
        DecryptionStream verificationStream = PGPainless.decryptAndOrVerify().onInputStream(signedIn)
                .withOptions(ConsumerOptions.get().addVerificationCert(signingCert));
        Streams.drain(verificationStream);
        verificationStream.close();

        List<SignatureVerification> sigs = verificationStream.getMetadata().getVerifiedSignatures();
        List<SubkeyIdentifier> sigKeys = sigs.stream().map(SignatureVerification::getSigningKey)
                .collect(Collectors.toList());
        assertTrue(sigKeys.contains(primaryKey));
        assertTrue(sigKeys.contains(signingKey1));
        assertTrue(sigKeys.contains(signingKey2));
    }

    @Test
    public void inlineSignWithSingleSubkey() throws PGPException, IOException {
        ByteArrayInputStream dataIn = new ByteArrayInputStream("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream signingStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(ProducerOptions.sign(SigningOptions.get().addInlineSignature(protector, signingKey, signingKey1.getKeyId())));
        Streams.pipeAll(dataIn, signingStream);
        signingStream.close();

        ByteArrayInputStream signedIn = new ByteArrayInputStream(out.toByteArray());
        DecryptionStream verificationStream = PGPainless.decryptAndOrVerify().onInputStream(signedIn)
                .withOptions(ConsumerOptions.get().addVerificationCert(signingCert));
        Streams.drain(verificationStream);
        verificationStream.close();

        List<SignatureVerification> sigs = verificationStream.getMetadata().getVerifiedSignatures();
        assertEquals(1, sigs.size());
        assertEquals(signingKey1, sigs.get(0).getSigningKey());
    }

}
