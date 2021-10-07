// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.key.TestKeys;

public class ArmorUtilsTest {

    @Test
    public void testParseArmorHeader() throws IOException {
        String armoredKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "Version: BCPG v1.68\n" +
                "Hash: SHA512\n" +
                "Comment: This is a comment\n" +
                "Comment: This is another comment\n" +
                "\n" +
                "mDMEYJ/OsRYJKwYBBAHaRw8BAQdAaOs6IF1fWhN/dqwfSrxD/MNnBXVEx8WlecCa\n" +
                "cAiSCv60DnRlc3RAdGVzdC50ZXN0iHgEExYKACAFAmCfzrECGwMFFgIDAQAECwkI\n" +
                "BwUVCgkICwIeAQIZAQAKCRD2lyhrcqSwzDWIAP9i6LfaUp3gEhGQR3FojyhfPVB1\n" +
                "Y3bBU7osj/XOpEN6RAD/YzL9VO45yYp1IUvU1NQWJy42ZHHZy4ZrjULLQ/HbpQW4\n" +
                "OARgn86xEgorBgEEAZdVAQUBAQdASAPiuOakmDdL0HaSemeNB5Hl7lniD8vCeFgz\n" +
                "OcgWjSYDAQgHiHUEGBYKAB0FAmCfzrECGwwFFgIDAQAECwkIBwUVCgkICwIeAQAK\n" +
                "CRD2lyhrcqSwzJ4HAQD7uDYyEsqEGHI4LULfphxPSC5nG9pbBA3mL4ze46uDmAD/\n" +
                "aea172D0TfBwQXZxujLECTce5/1jyTaM+ee8gfw1BQ8=\n" +
                "=RQHd\n" +
                "-----END PGP PUBLIC KEY BLOCK-----";

        ByteArrayInputStream in = new ByteArrayInputStream(armoredKey.getBytes(StandardCharsets.UTF_8));
        ArmoredInputStream armorIn = ArmoredInputStreamFactory.get(in);

        // No charset
        assertEquals(0, ArmorUtils.getCharsetHeaderValues(armorIn).size());

        // Version
        List<String> versionHeader = ArmorUtils.getVersionHeaderValues(armorIn);
        assertEquals(1, versionHeader.size());
        assertEquals("BCPG v1.68", versionHeader.get(0));

        // Hash
        List<String> hashHeader = ArmorUtils.getHashHeaderValues(armorIn);
        assertEquals(1, hashHeader.size());
        assertEquals("SHA512", hashHeader.get(0));
        List<HashAlgorithm> hashes = ArmorUtils.getHashAlgorithms(armorIn);
        assertEquals(HashAlgorithm.SHA512, hashes.get(0));

        // Comment
        List<String> commentHeader = ArmorUtils.getCommendHeaderValues(armorIn);
        assertEquals(2, commentHeader.size());
        assertEquals("This is a comment", commentHeader.get(0));
        assertEquals("This is another comment", commentHeader.get(1));

        // MessageID
        assertEquals(0, ArmorUtils.getMessageIdHeaderValues(armorIn).size());
    }

    @Test
    public void testSetMessageId() {
        ArmoredOutputStream armor = new ArmoredOutputStream(new ByteArrayOutputStream());
        ArmorUtils.addMessageIdHeader(armor, "abcdefghi01234567890123456789012");

        assertThrows(NullPointerException.class, () -> ArmorUtils.addMessageIdHeader(armor, null));
        assertThrows(IllegalArgumentException.class, () -> ArmorUtils.addMessageIdHeader(armor, "tooShort"));
        assertThrows(IllegalArgumentException.class, () -> ArmorUtils.addMessageIdHeader(armor, "toLooooooooooooooooooooooooooooooooooong"));
        assertThrows(IllegalArgumentException.class, () -> ArmorUtils.addMessageIdHeader(armor, "contains spaces 7890123456789012"));
        assertThrows(IllegalArgumentException.class, () -> ArmorUtils.addMessageIdHeader(armor, "contains\nnewlines\n12345678901234"));
    }

    @Test
    public void testAddCommentAndHashHeaders() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armor = new ArmoredOutputStream(out);
        ArmorUtils.addCommentHeader(armor, "This is a comment.");
        ArmorUtils.addHashAlgorithmHeader(armor, HashAlgorithm.SHA224);

        secretKeys.encode(armor);
        armor.close();

        String armored = out.toString();
        assertTrue(armored.contains("Hash: SHA224"));
        assertTrue(armored.contains("Comment: This is a comment."));
    }

    @Test
    public void toAsciiArmoredString() throws PGPException, IOException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        secretKeys.encode(bytes);

        ByteArrayInputStream in = new ByteArrayInputStream(bytes.toByteArray());
        String ascii = ArmorUtils.toAsciiArmoredString(in);
        assertTrue(ascii.startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----\n"));
    }

    @Test
    public void testSetCustomVersionHeader() throws IOException {
        ArmoredOutputStreamFactory.setVersionInfo("MyVeryFirstOpenPGPProgram 1.0");
        ArmoredOutputStreamFactory.setComment("This is a comment\nThat spans multiple\nLines!");

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armorOut = ArmoredOutputStreamFactory.get(out);

        byte[] data = "This is a very secret message that nobody is allowed to read.".getBytes(StandardCharsets.UTF_8);
        armorOut.write(data);
        armorOut.close();

        assertEquals("-----BEGIN PGP MESSAGE-----\n" +
                "Version: MyVeryFirstOpenPGPProgram 1.0\n" +
                "Comment: This is a comment\n" +
                "Comment: That spans multiple\n" +
                "Comment: Lines!\n" +
                "\n" +
                "VGhpcyBpcyBhIHZlcnkgc2VjcmV0IG1lc3NhZ2UgdGhhdCBub2JvZHkgaXMgYWxs\n" +
                "b3dlZCB0byByZWFkLg==\n" +
                "=XMZb\n" +
                "-----END PGP MESSAGE-----\n", out.toString());
    }

    @Test
    public void decodeExampleTest() throws IOException, PGPException {
        String armored = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: OpenPrivacy 0.99\n" +
                "\n" +
                "yDgBO22WxBHv7O8X7O/jygAEzol56iUKiXmV+XmpCtmpqQUKiQrFqclFqUDBovzS\n" +
                "vBSFjNSiVHsuAA==\n" +
                "=njUN\n" +
                "-----END PGP MESSAGE-----";
        InputStream inputStream = PGPUtil.getDecoderStream(new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8)));
        PGPObjectFactory factory = new BcPGPObjectFactory(inputStream);
        PGPCompressedData compressed = (PGPCompressedData) factory.nextObject();
        factory = new BcPGPObjectFactory(compressed.getDataStream());
        PGPLiteralData literal = (PGPLiteralData) factory.nextObject();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        assertEquals("_CONSOLE", literal.getFileName());
        Streams.pipeAll(literal.getInputStream(), out);
        assertEquals("Can't anyone keep a secret around here?\n", out.toString());
    }

    @AfterAll
    public static void resetHeaders() {
        ArmoredOutputStreamFactory.resetComment();
        ArmoredOutputStreamFactory.resetVersionInfo();
    }
}
