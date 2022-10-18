// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.JUtils;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.OpenPgpMetadata;
import org.pgpainless.decryption_verification.SignatureVerification;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionResult;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.xdh.XDHSpec;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.timeframe.TestTimeFrameProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class GenerateKeyWithoutUserIdTest {

    @Test
    public void generateKeyWithoutUserId() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        Date now = new Date();
        Date expirationDate = TestTimeFrameProvider.defaultExpirationForCreationDate(now);
        PGPSecretKeyRing secretKey = PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.CERTIFY_OTHER).setKeyCreationDate(now))
                .addSubkey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.SIGN_DATA).setKeyCreationDate(now))
                .addSubkey(KeySpec.getBuilder(KeyType.XDH(XDHSpec._X25519), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE).setKeyCreationDate(now))
                .setExpirationDate(expirationDate)
                .build();

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKey);
        assertNull(info.getPrimaryUserId());
        assertTrue(info.getUserIds().isEmpty());
        JUtils.assertDateEquals(expirationDate, info.getPrimaryKeyExpirationDate());

        InputStream plaintextIn = new ByteArrayInputStream("Hello, World!\n".getBytes());
        ByteArrayOutputStream ciphertextOut = new ByteArrayOutputStream();
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKey);

        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(ciphertextOut)
                .withOptions(ProducerOptions.signAndEncrypt(
                        EncryptionOptions.get()
                                .addRecipient(certificate),
                        SigningOptions.get()
                                .addSignature(protector, secretKey)
                ));
        Streams.pipeAll(plaintextIn, encryptionStream);
        encryptionStream.close();

        EncryptionResult result = encryptionStream.getResult();
        assertTrue(result.isEncryptedFor(certificate));

        ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(ciphertextOut.toByteArray());
        ByteArrayOutputStream plaintextOut = new ByteArrayOutputStream();
        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(ciphertextIn)
                .withOptions(ConsumerOptions.get()
                        .addDecryptionKey(secretKey)
                        .addVerificationCert(certificate));

        Streams.pipeAll(decryptionStream, plaintextOut);
        decryptionStream.close();

        OpenPgpMetadata metadata = decryptionStream.getResult();

        assertTrue(metadata.containsVerifiedSignatureFrom(certificate),
                failuresToString(metadata.getInvalidInbandSignatures()));
        assertTrue(metadata.isEncrypted());
    }

    private static String failuresToString(List<SignatureVerification.Failure> failureList) {
        StringBuilder sb = new StringBuilder();
        for (SignatureVerification.Failure failure : failureList) {
            sb.append(failure.toString()).append('\n');
        }
        return sb.toString();
    }
}
