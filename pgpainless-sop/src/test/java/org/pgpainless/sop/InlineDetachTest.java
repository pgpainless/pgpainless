// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import sop.ByteArrayAndResult;
import sop.SOP;
import sop.Signatures;
import sop.Verification;
import sop.enums.InlineSignAs;

public class InlineDetachTest {

    private static final SOP sop = new SOPImpl();
    @Test
    public void detachCleartextSignedMessage() throws IOException {
        byte[] key = sop.generateKey()
                .userId("Alice <alice@pgpainless.org>")
                .generate()
                .getBytes();
        byte[] cert = sop.extractCert().key(key).getBytes();
        PGPSecretKeyRing secretKey = PGPainless.readKeyRing().secretKeyRing(key);

        // Create a cleartext signed message
        byte[] data = "Hello, World\n".getBytes(StandardCharsets.UTF_8);
        byte[] cleartextSigned = sop.inlineSign()
                .key(key)
                .withKeyPassword("sw0rdf1sh")
                .mode(InlineSignAs.CleartextSigned)
                .data(data).getBytes();

        // actually detach the message
        ByteArrayAndResult<Signatures> detachedMsg = sop.inlineDetach()
                .message(cleartextSigned)
                .toByteArrayAndResult();

        byte[] message = detachedMsg.getBytes();
        byte[] signature = detachedMsg.getResult().getBytes();

        List<Verification> verificationList = sop.verify()
                .cert(cert)
                .signatures(signature)
                .data(message);

        assertFalse(verificationList.isEmpty());
        assertEquals(1, verificationList.size());
        assertEquals(new OpenPgpV4Fingerprint(secretKey).toString(), verificationList.get(0).getSigningCertFingerprint());
        assertArrayEquals(data, message);
    }

    @Test
    public void detachInbandSignedMessage() throws IOException {
        byte[] key = sop.generateKey()
                .userId("Alice <alice@pgpainless.org>")
                .generate()
                .getBytes();
        byte[] cert = sop.extractCert().key(key).getBytes();

        byte[] data = "Hello, World\n".getBytes(StandardCharsets.UTF_8);
        byte[] inlineSigned = sop.inlineSign()
                .key(key)
                .data(data).getBytes();

        // actually detach the message
        ByteArrayAndResult<Signatures> detachedMsg = sop.inlineDetach()
                .message(inlineSigned)
                .toByteArrayAndResult();

        byte[] message = detachedMsg.getBytes();
        byte[] signature = detachedMsg.getResult().getBytes();

        List<Verification> verificationList = sop.verify()
                .cert(cert)
                .signatures(signature)
                .data(message);

        assertFalse(verificationList.isEmpty());
        assertEquals(1, verificationList.size());
        assertArrayEquals(data, message);
    }
}
