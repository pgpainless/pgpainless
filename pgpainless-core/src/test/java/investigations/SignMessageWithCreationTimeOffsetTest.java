// SPDX-FileCopyrightText: 2025 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package investigations;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.util.io.Streams;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.OpenPGPKeyVersion;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.MessageMetadata;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.BaseSignatureSubpackets;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SignMessageWithCreationTimeOffsetTest {

    @Test
    public void signMessageInThePast() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();
        Date now = new Date();
        Date oneHourAgo = new Date(now.getTime() - (1000 * 60 * 60));
        Date twoHoursAgo = new Date(now.getTime() - (2 * 1000 * 60 * 60));

        OpenPGPKey key = api.generateKey(OpenPGPKeyVersion.v4, twoHoursAgo)
                .modernKeyRing("Alice <alice@pgpainless.org>");

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        EncryptionStream encOut = api.generateMessage()
                .onOutputStream(bOut)
                .withOptions(ProducerOptions.sign(
                        SigningOptions.get()
                                .addInlineSignature(
                                        SecretKeyRingProtector.unprotectedKeys(),
                                        key,
                                        null,
                                        DocumentSignatureType.BINARY_DOCUMENT,
                                        new BaseSignatureSubpackets.Callback() {
                                            @Override
                                            public void modifyHashedSubpackets(@NotNull BaseSignatureSubpackets hashedSubpackets) {
                                                hashedSubpackets.setSignatureCreationTime(oneHourAgo);
                                            }
                                        })
                ));

        encOut.write("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        encOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        DecryptionStream decIn = api.processMessage()
                .onInputStream(bIn)
                .withOptions(ConsumerOptions.get()
                        .addVerificationCert(key.toCertificate()));

        Streams.drain(decIn); // Or pipeAll to plaintext out
        decIn.close();

        MessageMetadata metadata = decIn.getMetadata();
        assertTrue(metadata.isVerifiedSignedBy(key.toCertificate()));
    }

    @Test
    public void testSignMessageInFuture() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();
        Date now = new Date();
        Date inOneHour = new Date(now.getTime() + 1000 * 60 * 60);

        OpenPGPKey key = api.generateKey().modernKeyRing("Alice <alice@pgpainless.org>");

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        EncryptionStream encOut = api.generateMessage()
                .onOutputStream(bOut)
                .withOptions(ProducerOptions.sign(SigningOptions.get()
                        .addInlineSignature(SecretKeyRingProtector.unprotectedKeys(), key, null, DocumentSignatureType.BINARY_DOCUMENT, new BaseSignatureSubpackets.Callback() {
                            @Override
                            public void modifyHashedSubpackets(@NotNull BaseSignatureSubpackets hashedSubpackets) {
                                hashedSubpackets.setSignatureCreationTime(inOneHour);
                            }
                        })));

        encOut.write("Hello, World!\n".getBytes(StandardCharsets.UTF_8));
        encOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        DecryptionStream decIn = api.processMessage()
                .onInputStream(bIn)
                .withOptions(ConsumerOptions.get()
                        .addVerificationCert(key.toCertificate()));

        Streams.drain(decIn);
        decIn.close();

        MessageMetadata metadata = decIn.getMetadata();
        assertFalse(metadata.isVerifiedSignedBy(key.toCertificate()));

        // Try again, adjusting validity period
        bIn = new ByteArrayInputStream(bOut.toByteArray());
        decIn = api.processMessage()
                .onInputStream(bIn)
                .withOptions(ConsumerOptions.get()
                        .verifyNotAfter(inOneHour) // is set to 'now' by default, so to allow verifying future sigs, we need to adjust
                        .addVerificationCert(key.toCertificate()));

        Streams.drain(decIn);
        decIn.close();

        metadata = decIn.getMetadata();
        assertTrue(metadata.isVerifiedSignedBy(key.toCertificate()));
    }
}
