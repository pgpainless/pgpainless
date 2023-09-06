// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import org.junit.JUtils;
import org.junit.jupiter.api.Test;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.StreamEncoding;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.util.DateUtil;

import java.util.Date;
import java.util.Iterator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class MessageMetadataTest {

    @Test
    public void processTestMessage_COMP_ENC_ENC_LIT() {
        // Note: COMP of ENC does not make sense, since ENC is indistinguishable from randomness
        //  and randomness cannot be encrypted.
        //  For the sake of testing though, this is okay.
        MessageMetadata.Message message = new MessageMetadata.Message();

        MessageMetadata.CompressedData compressedData = new MessageMetadata.CompressedData(CompressionAlgorithm.ZIP, message.getDepth() + 1);
        MessageMetadata.EncryptedData encryptedData = new MessageMetadata.EncryptedData(SymmetricKeyAlgorithm.AES_128, compressedData.getDepth() + 1);
        MessageMetadata.EncryptedData encryptedData1 = new MessageMetadata.EncryptedData(SymmetricKeyAlgorithm.AES_256, encryptedData.getDepth() + 1);
        MessageMetadata.LiteralData literalData = new MessageMetadata.LiteralData();

        message.setChild(compressedData);
        compressedData.setChild(encryptedData);
        encryptedData.setChild(encryptedData1);
        encryptedData1.setChild(literalData);

        MessageMetadata metadata = new MessageMetadata(message);

        // Check encryption algs
        assertEquals(SymmetricKeyAlgorithm.AES_128, metadata.getEncryptionAlgorithm(), "getEncryptionAlgorithm() returns alg of outermost EncryptedData");
        Iterator<SymmetricKeyAlgorithm> encryptionAlgs = metadata.getEncryptionAlgorithms();
        assertTrue(encryptionAlgs.hasNext(), "There is at least one EncryptedData child");
        assertTrue(encryptionAlgs.hasNext(), "The child is still there");
        assertEquals(SymmetricKeyAlgorithm.AES_128, encryptionAlgs.next(), "The first algo is AES128");
        assertTrue(encryptionAlgs.hasNext(), "There is another EncryptedData");
        assertTrue(encryptionAlgs.hasNext(), "There is *still* another EncryptedData");
        assertEquals(SymmetricKeyAlgorithm.AES_256, encryptionAlgs.next(), "The second algo is AES256");
        assertFalse(encryptionAlgs.hasNext(), "There is no more EncryptedData");
        assertFalse(encryptionAlgs.hasNext(), "There *still* is no more EncryptedData");

        assertEquals(CompressionAlgorithm.ZIP, metadata.getCompressionAlgorithm(), "getCompressionAlgorithm() returns alg of outermost CompressedData");
        Iterator<CompressionAlgorithm> compAlgs = metadata.getCompressionAlgorithms();
        assertTrue(compAlgs.hasNext());
        assertTrue(compAlgs.hasNext());
        assertEquals(CompressionAlgorithm.ZIP, compAlgs.next());
        assertFalse(compAlgs.hasNext());
        assertFalse(compAlgs.hasNext());

        assertEquals("", metadata.getFilename());
        JUtils.assertDateEquals(new Date(0L), metadata.getModificationDate());
        assertEquals(StreamEncoding.BINARY, metadata.getLiteralDataEncoding());
    }

    @Test
    public void testProcessLiteralDataMessage() {
        MessageMetadata.LiteralData literalData = new MessageMetadata.LiteralData(
                "collateral_murder.zip",
                DateUtil.parseUTCDate("2010-04-05 10:12:03 UTC"),
                StreamEncoding.BINARY);
        MessageMetadata.Message message = new MessageMetadata.Message();
        message.setChild(literalData);

        MessageMetadata metadata = new MessageMetadata(message);
        assertNull(metadata.getCompressionAlgorithm());
        assertNull(metadata.getEncryptionAlgorithm());
        assertEquals("collateral_murder.zip", metadata.getFilename());
        assertEquals(DateUtil.parseUTCDate("2010-04-05 10:12:03 UTC"), metadata.getModificationDate());
        assertEquals(StreamEncoding.BINARY, metadata.getLiteralDataEncoding());
    }
}
