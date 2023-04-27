// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import sop.ByteArrayAndResult;
import sop.SOP;
import sop.Signatures;
import sop.Verification;
import sop.enums.InlineSignAs;
import sop.enums.SignatureMode;
import sop.exception.SOPGPException;
import sop.testsuite.assertions.VerificationListAssert;

public class InlineDetachTest {

    private static final SOP sop = new SOPImpl();

    /**
     * Construct a message which is signed using the cleartext signature framework.
     * The message consists of an armor header followed by the dash-escaped message data, followed by an armored signature.
     *
     * Detaching must result in the unescaped message data plus the signature packet.
     * Verifying the signature must work.
     *
     * @throws IOException in case of an IO error
     */
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
                .mode(InlineSignAs.clearsigned)
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

        VerificationListAssert.assertThatVerificationList(verificationList)
                .hasSingleItem()
                .issuedBy(new OpenPgpV4Fingerprint(secretKey).toString())
                .hasMode(SignatureMode.text);

        assertArrayEquals(data, message);
    }

    /**
     * Construct a message which is inline-signed.
     * The message consists of a compressed data packet containing an OnePassSignature, a literal data packet and
     * a signature packet.
     *
     * Detaching the message must result in the contents of the literal data packet, plus the signature packet.
     * Verification must work.
     *
     * @throws IOException in case of an IO error
     */
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

        VerificationListAssert.assertThatVerificationList(verificationList)
                .hasSingleItem()
                .hasMode(SignatureMode.binary);

        assertArrayEquals(data, message);
    }

    /**
     * Construct a message which consists of a literal data packet followed by a signatures block.
     * Detaching it must result in the contents of the literal data packet plus the signatures block.
     *
     * Verification must still work.
     *
     * @throws IOException in case of an IO error
     */
    @Test
    public void detachOpenPgpMessage() throws IOException {
        byte[] key = sop.generateKey()
                .userId("Alice <alice@pgpainless.org>")
                .generate()
                .getBytes();
        byte[] cert = sop.extractCert().key(key).getBytes();

        byte[] data = "Hello, World\n".getBytes(StandardCharsets.UTF_8);
        byte[] inlineSigned = sop.inlineSign()
                .key(key)
                .data(data).getBytes();

        ByteArrayOutputStream literalDataAndSignatures = new ByteArrayOutputStream();
        ArmoredInputStream armorIn = new ArmoredInputStream(new ByteArrayInputStream(inlineSigned));
        PGPObjectFactory objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(armorIn);
        Object next;
        while ((next = objectFactory.nextObject()) != null) {
            if (next instanceof PGPCompressedData) {
                PGPCompressedData compressedData = (PGPCompressedData) next;
                try {
                    objectFactory = ImplementationFactory.getInstance().getPGPObjectFactory(compressedData.getDataStream());
                } catch (PGPException e) {
                    throw new SOPGPException.BadData("Cannot decompress compressed data", e);
                }
                continue;
            }
            if (next instanceof PGPLiteralData) {
                PGPLiteralData litDat = (PGPLiteralData) next;
                PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
                OutputStream litOut = litGen.open(literalDataAndSignatures, (char) litDat.getFormat(), litDat.getFileName(), litDat.getModificationTime(), new byte[8192]);
                Streams.pipeAll(litDat.getDataStream(), litOut);
                litOut.close();
                continue;
            }

            if (next instanceof PGPSignatureList) {
                PGPSignatureList signatures = (PGPSignatureList) next;
                for (PGPSignature signature : signatures) {
                    signature.encode(literalDataAndSignatures);
                }
            }
        }

        // actually detach the message
        ByteArrayAndResult<Signatures> detachedMsg = sop.inlineDetach()
                .message(literalDataAndSignatures.toByteArray())
                .toByteArrayAndResult();

        byte[] message = detachedMsg.getBytes();
        byte[] signature = detachedMsg.getResult().getBytes();

        List<Verification> verificationList = sop.verify()
                .cert(cert)
                .signatures(signature)
                .data(message);

        VerificationListAssert.assertThatVerificationList(verificationList)
                .hasSingleItem()
                .hasMode(SignatureMode.binary);

        assertArrayEquals(data, message);
    }
}
