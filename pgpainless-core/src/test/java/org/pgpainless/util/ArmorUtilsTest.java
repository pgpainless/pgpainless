/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
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
}
