// SPDX-FileCopyrightText: 2026 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPSignature;
import org.bouncycastle.util.io.Streams;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.OpenPGPKeyVersion;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.signature.subpackets.BaseSignatureSubpackets;
import org.pgpainless.util.DateUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DocumentSignatureExpirationTests {

    @Test
    public void testInlineSignatureExpiration() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();

        // key creation
        Date t0 = DateUtil.parseUTCDate("2026-06-01 10:00:00 UTC");

        // signature creation
        Date t1 = DateUtil.parseUTCDate("2026-06-01 11:00:00 UTC");

        // first signature validation
        Date t2 = DateUtil.parseUTCDate("2026-06-01 11:30:00 UTC");

        // signature expiration
        Date t3 = DateUtil.parseUTCDate("2026-06-01 12:00:00 UTC");

        // second signature validation
        Date t4 = DateUtil.parseUTCDate("2026-06-01 12:30:00 UTC");

        OpenPGPKey key = api.generateKey(OpenPGPKeyVersion.v4, t0)
                .modernKeyRing("Alice <alice@pgpainless.org>");

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        EncryptionStream eOut = api.generateMessage()
                .onOutputStream(bOut)
                .withOptions(ProducerOptions.sign(SigningOptions.get(api)
                        .addInlineSignature(SecretKeyRingProtector.unprotectedKeys(),
                                key,
                                "Alice <alice@pgpainless.org>",
                                DocumentSignatureType.BINARY_DOCUMENT,
                                new BaseSignatureSubpackets.Callback() {
                                    @Override
                                    public void modifyHashedSubpackets(@NotNull BaseSignatureSubpackets hashedSubpackets) {
                                        hashedSubpackets.setSignatureCreationTime(t1);
                                        hashedSubpackets.setSignatureExpirationTime(t1, t3);
                                    }
                                })));
        eOut.write("Hello World".getBytes());
        eOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        DecryptionStream dIn = api.processMessage().onInputStream(bIn)
                .withOptions(ConsumerOptions.get(api)
                        .verifyNotAfter(t2)
                        .addVerificationCert(key.toCertificate()));
        Streams.drain(dIn);
        dIn.close();
        assertFalse(dIn.getMetadata().getVerifiedSignatures().isEmpty(),
                "At t2, the document signature MUST be valid");

        bIn = new ByteArrayInputStream(bOut.toByteArray());
        dIn = api.processMessage().onInputStream(bIn)
                .withOptions(ConsumerOptions.get(api)
                        .verifyNotAfter(t4)
                        .addVerificationCert(key.toCertificate()));
        Streams.drain(dIn);
        dIn.close();
        assertTrue(dIn.getMetadata().getVerifiedSignatures().isEmpty(),
                "At t4, the document signature MUST be expired");
    }

    @Test
    public void testCleartextSignatureExpiration() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();

        // key creation
        Date t0 = DateUtil.parseUTCDate("2026-06-01 10:00:00 UTC");

        // signature creation
        Date t1 = DateUtil.parseUTCDate("2026-06-01 11:00:00 UTC");

        // first signature validation
        Date t2 = DateUtil.parseUTCDate("2026-06-01 11:30:00 UTC");

        // signature expiration
        Date t3 = DateUtil.parseUTCDate("2026-06-01 12:00:00 UTC");

        // second signature validation
        Date t4 = DateUtil.parseUTCDate("2026-06-01 12:30:00 UTC");

        OpenPGPKey key = api.generateKey(OpenPGPKeyVersion.v4, t0)
                .modernKeyRing("Alice <alice@pgpainless.org>");

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        EncryptionStream eOut = api.generateMessage()
                .onOutputStream(bOut)
                .withOptions(ProducerOptions.sign(SigningOptions.get(api)
                        .addDetachedSignature(SecretKeyRingProtector.unprotectedKeys(),
                                key,
                                "Alice <alice@pgpainless.org>",
                                DocumentSignatureType.BINARY_DOCUMENT,
                                new BaseSignatureSubpackets.Callback() {
                                    @Override
                                    public void modifyHashedSubpackets(@NotNull BaseSignatureSubpackets hashedSubpackets) {
                                        hashedSubpackets.setSignatureCreationTime(t1);
                                        hashedSubpackets.setSignatureExpirationTime(t1, t3);
                                    }
                                })).setCleartextSigned());
        eOut.write("Hello World".getBytes());
        eOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        DecryptionStream dIn = api.processMessage().onInputStream(bIn)
                .withOptions(ConsumerOptions.get(api)
                        .verifyNotAfter(t2)
                        .addVerificationCert(key.toCertificate()));
        Streams.drain(dIn);
        dIn.close();
        assertFalse(dIn.getMetadata().getVerifiedSignatures().isEmpty(),
                "At t2, the document signature MUST be valid");

        bIn = new ByteArrayInputStream(bOut.toByteArray());
        dIn = api.processMessage().onInputStream(bIn)
                .withOptions(ConsumerOptions.get(api)
                        .verifyNotAfter(t4)
                        .addVerificationCert(key.toCertificate()));
        Streams.drain(dIn);
        dIn.close();
        assertTrue(dIn.getMetadata().getVerifiedSignatures().isEmpty(),
                "At t4, the document signature MUST be expired");
    }

    @Test
    public void testDetachedSignatureExpiration() throws PGPException, IOException {
        PGPainless api = PGPainless.getInstance();

        // key creation
        Date t0 = DateUtil.parseUTCDate("2026-06-01 10:00:00 UTC");

        // signature creation
        Date t1 = DateUtil.parseUTCDate("2026-06-01 11:00:00 UTC");

        // first signature validation
        Date t2 = DateUtil.parseUTCDate("2026-06-01 11:30:00 UTC");

        // signature expiration
        Date t3 = DateUtil.parseUTCDate("2026-06-01 12:00:00 UTC");

        // second signature validation
        Date t4 = DateUtil.parseUTCDate("2026-06-01 12:30:00 UTC");

        OpenPGPKey key = api.generateKey(OpenPGPKeyVersion.v4, t0)
                .modernKeyRing("Alice <alice@pgpainless.org>");

        byte[] msg = "Hello, World!\n".getBytes(StandardCharsets.UTF_8);
        EncryptionStream eOut = api.generateMessage()
                .discardOutput()
                .withOptions(ProducerOptions.sign(SigningOptions.get(api)
                        .addDetachedSignature(SecretKeyRingProtector.unprotectedKeys(),
                                key,
                                "Alice <alice@pgpainless.org>",
                                DocumentSignatureType.BINARY_DOCUMENT,
                                new BaseSignatureSubpackets.Callback() {
                                    @Override
                                    public void modifyHashedSubpackets(@NotNull BaseSignatureSubpackets hashedSubpackets) {
                                        hashedSubpackets.setSignatureCreationTime(t1);
                                        hashedSubpackets.setSignatureExpirationTime(t1, t3);
                                    }
                                })));
        eOut.write(msg);
        eOut.close();
        OpenPGPSignature.OpenPGPDocumentSignature detached = eOut.getResult().getDetachedDocumentSignatures().getSignatures().get(0);

        ByteArrayInputStream bIn = new ByteArrayInputStream(msg);
        DecryptionStream dIn = api.processMessage().onInputStream(bIn)
                .withOptions(ConsumerOptions.get(api)
                        .verifyNotAfter(t2)
                        .addVerificationOfDetachedSignature(detached)
                        .addVerificationCert(key.toCertificate()));
        Streams.drain(dIn);
        dIn.close();
        assertFalse(dIn.getMetadata().getVerifiedSignatures().isEmpty(),
                "At t2, the document signature MUST be valid");

        bIn = new ByteArrayInputStream(msg);
        dIn = api.processMessage().onInputStream(bIn)
                .withOptions(ConsumerOptions.get(api)
                        .verifyNotAfter(t4)
                        .addVerificationOfDetachedSignature(detached)
                        .addVerificationCert(key.toCertificate()));
        Streams.drain(dIn);
        dIn.close();
        assertTrue(dIn.getMetadata().getVerifiedSignatures().isEmpty(),
                "At t4, the document signature MUST be expired");
    }
}
