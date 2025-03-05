// SPDX-FileCopyrightText: 2023 Bastien Jansen
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPV3SignatureGenerator;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.SecretKeyRingProtector;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertTrue;

class VerifyVersion3SignaturePacketTest {


    protected static final byte[] DATA = "hello".getBytes(StandardCharsets.UTF_8);

    @Test
    void verifyDetachedVersion3Signature() throws PGPException, IOException {
        PGPSignature version3Signature = generateV3Signature();

        ConsumerOptions options = ConsumerOptions.get()
                .addVerificationCert(TestKeys.getEmilPublicKeyRing())
                .addVerificationOfDetachedSignatures(new ByteArrayInputStream(version3Signature.getEncoded()));

        DecryptionStream verifier = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(DATA))
                .withOptions(options);

        MessageMetadata metadata = processSignedData(verifier);
        assertTrue(metadata.isVerifiedSignedBy(TestKeys.getEmilPublicKeyRing()));
    }

    private static PGPSignature generateV3Signature() throws IOException, PGPException {
        PGPContentSignerBuilder builder = ImplementationFactory.getInstance().getPGPContentSignerBuilder(PublicKeyAlgorithm.ECDSA, HashAlgorithm.SHA512);
        PGPV3SignatureGenerator signatureGenerator = new PGPV3SignatureGenerator(builder);

        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();
        PGPPrivateKey privateKey = secretKeys.getSecretKey().extractPrivateKey(protector.getDecryptor(secretKeys.getSecretKey().getKeyID()));

        signatureGenerator.init(SignatureType.CANONICAL_TEXT_DOCUMENT.getCode(), privateKey);
        signatureGenerator.update(DATA);

        return signatureGenerator.generate();
    }

    private MessageMetadata processSignedData(DecryptionStream verifier) throws IOException {
        Streams.drain(verifier);
        verifier.close();
        return verifier.getMetadata();
    }
}
