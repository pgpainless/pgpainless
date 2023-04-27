// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;
import sop.ByteArrayAndResult;
import sop.SOP;
import sop.Verification;
import sop.enums.InlineSignAs;
import sop.enums.SignatureMode;
import sop.testsuite.assertions.VerificationListAssert;

public class InlineSignVerifyRoundtripTest {

    private static final SOP sop = new SOPImpl();

    @Test
    public void testInlineSignAndVerifyWithCleartextSignatures() throws IOException {
        byte[] key = sop.generateKey()
                .userId("Werner")
                .withKeyPassword("sw0rdf1sh")
                .generate().getBytes();

        byte[] cert = sop.extractCert()
                .key(key).getBytes();

        byte[] message = "If you want something different, create a new protocol but don't try to\npush it onto a working system.\n".getBytes(StandardCharsets.UTF_8);

        byte[] inlineSigned = sop.inlineSign()
                .key(key)
                .withKeyPassword("sw0rdf1sh")
                .mode(InlineSignAs.clearsigned)
                .data(message).getBytes();

        ByteArrayAndResult<List<Verification>> result = sop.inlineVerify()
                .cert(cert)
                .data(inlineSigned)
                .toByteArrayAndResult();

        byte[] verified = result.getBytes();

        List<Verification> verificationList = result.getResult();
        VerificationListAssert.assertThatVerificationList(verificationList)
                .hasSingleItem()
                .hasMode(SignatureMode.text);

        assertArrayEquals(message, verified);
    }

    @Test
    public void testInlineSignAndVerifyWithBinarySignatures() throws IOException {
        byte[] key = sop.generateKey()
                .userId("Werner")
                .withKeyPassword("sw0rdf1sh")
                .generate().getBytes();

        byte[] cert = sop.extractCert()
                .key(key).getBytes();

        byte[] message = "Yes, this is what has been deployed worldwide for years in millions of\ninstallations (decryption wise) and is meanwhile in active use.\n".getBytes(StandardCharsets.UTF_8);

        byte[] inlineSigned = sop.inlineSign()
                .key(key)
                .withKeyPassword("sw0rdf1sh")
                .mode(InlineSignAs.binary)
                .data(message).getBytes();

        ByteArrayAndResult<List<Verification>> result = sop.inlineVerify()
                .cert(cert)
                .data(inlineSigned)
                .toByteArrayAndResult();

        byte[] verified = result.getBytes();

        List<Verification> verificationList = result.getResult();
        VerificationListAssert.assertThatVerificationList(verificationList)
                .hasSingleItem()
                .hasMode(SignatureMode.binary);

        assertArrayEquals(message, verified);
    }


    @Test
    public void testInlineSignAndVerifyWithTextSignatures() throws IOException {
        byte[] key = sop.generateKey()
                .userId("Mark")
                .withKeyPassword("y3110w5ubm4r1n3")
                .generate().getBytes();

        byte[] cert = sop.extractCert()
                .key(key).getBytes();

        byte[] message = "Give me a plaintext that I can sign and verify, pls.".getBytes(StandardCharsets.UTF_8);

        byte[] inlineSigned = sop.inlineSign()
                .key(key)
                .withKeyPassword("y3110w5ubm4r1n3")
                .mode(InlineSignAs.text)
                .data(message).getBytes();

        ByteArrayAndResult<List<Verification>> result = sop.inlineVerify()
                .cert(cert)
                .data(inlineSigned)
                .toByteArrayAndResult();

        byte[] verified = result.getBytes();

        List<Verification> verificationList = result.getResult();
        VerificationListAssert.assertThatVerificationList(verificationList)
                .hasSingleItem()
                .hasMode(SignatureMode.text);

        assertArrayEquals(message, verified);
    }

}
