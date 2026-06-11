// SPDX-FileCopyrightText: 2026 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.util.io.Streams;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.BaseSignatureSubpackets;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class IntendedRecipientFingerprintTest {

    @Test
    public void testRejectionOfSignaturesWithMismatchedIntendedRecipientFingerprint()
            throws PGPException, IOException {
        PGPainless api = new PGPainless();

        OpenPGPKey keyA = api.generateKey().modernKeyRing("Alice <alice@pgpainless.org>");
        OpenPGPKey keyB = api.generateKey().modernKeyRing("Bob <bob@pgpainless.org>");

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        EncryptionStream eOut = api.generateMessage()
                .onOutputStream(bOut)
                .withOptions(
                        ProducerOptions.signAndEncrypt(
                                EncryptionOptions.get(api)
                                        .addRecipient(keyA.toCertificate()),
                                SigningOptions.get(api)
                                        .addInlineSignature(SecretKeyRingProtector.unprotectedKeys(), keyA, null, DocumentSignatureType.BINARY_DOCUMENT, new BaseSignatureSubpackets.Callback() {
                                            @Override
                                            public void modifyHashedSubpackets(@NotNull BaseSignatureSubpackets hashedSubpackets) {
                                                // add mismatched intended recipient
                                                hashedSubpackets.addIntendedRecipientFingerprint(keyB);
                                            }
                                        })
                        )
                );
        eOut.write("Hello, World!".getBytes());
        eOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        DecryptionStream dIn = api.processMessage()
                .onInputStream(bIn)
                .withOptions(ConsumerOptions.get(api)
                        .setVerifyIntendedRecipients(true)
                        .addDecryptionKey(keyA)
                        .addVerificationCert(keyA));
        Streams.drain(dIn);
        dIn.close();
        MessageMetadata metadata = dIn.getMetadata();

        assertFalse(metadata.isVerifiedSignedBy(keyA));
        assertTrue(metadata.getRejectedInlineSignatures()
                .get(0)
                .getValidationException()
                .getMessage().contains("IntendedRecipientFingerprint"));
    }
}
