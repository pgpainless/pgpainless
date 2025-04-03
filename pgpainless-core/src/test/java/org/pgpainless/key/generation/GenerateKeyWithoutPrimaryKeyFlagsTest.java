// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.MessageMetadata;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionResult;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.exception.KeyException;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve;
import org.pgpainless.key.generation.type.xdh_legacy.XDHLegacySpec;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;

public class GenerateKeyWithoutPrimaryKeyFlagsTest {

    @Test
    public void generateKeyWithoutCertifyKeyFlag_cannotCertifyThirdParties() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();
        OpenPGPKey key = api.buildKey().setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519)))
                .addSubkey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.SIGN_DATA))
                .addSubkey(KeySpec.getBuilder(KeyType.XDH_LEGACY(XDHLegacySpec._X25519), KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS))
                .addUserId("Alice")
                .build();
        OpenPGPCertificate cert = key.toCertificate();

        KeyRingInfo info = api.inspect(key);
        assertTrue(info.getValidUserIds().contains("Alice"));

        KeyIdentifier primaryKeyIdentifier = info.getKeyIdentifier();
        assertTrue(info.getKeyFlagsOf("Alice").isEmpty());
        assertTrue(info.getKeyFlagsOf(primaryKeyIdentifier).isEmpty());
        assertFalse(info.isUsableForThirdPartyCertification());

        // Key without CERTIFY_OTHER flag cannot be used to certify other keys
        OpenPGPCertificate thirdPartyCert = TestKeys.getCryptieCertificate();
        assertThrows(KeyException.UnacceptableThirdPartyCertificationKeyException.class, () ->
                api.generateCertification().delegateTrust(thirdPartyCert)
                        .withKey(key, SecretKeyRingProtector.unprotectedKeys()));

        // Key without CERTIFY_OTHER flags is usable for encryption and signing
        ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = api.generateMessage()
                .onOutputStream(ciphertext)
                .withOptions(ProducerOptions.signAndEncrypt(
                        EncryptionOptions.get().addRecipient(cert),
                        SigningOptions.get().addInlineSignature(SecretKeyRingProtector.unprotectedKeys(), key, DocumentSignatureType.BINARY_DOCUMENT)
                ));
        encryptionStream.write("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        encryptionStream.close();
        EncryptionResult result = encryptionStream.getResult();
        assertTrue(result.isEncryptedFor(cert));

        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(ciphertext.toByteArray()))
                .withOptions(ConsumerOptions.get().addDecryptionKey(key)
                        .addVerificationCert(cert));

        ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, plaintext);
        decryptionStream.close();

        MessageMetadata metadata = decryptionStream.getMetadata();
        assertTrue(metadata.isEncryptedFor(cert));
        assertTrue(metadata.isVerifiedSignedBy(cert));
    }
}
