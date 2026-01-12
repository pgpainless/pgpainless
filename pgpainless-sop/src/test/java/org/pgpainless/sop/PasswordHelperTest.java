// SPDX-FileCopyrightText: 2026 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import sop.exception.SOPGPException;
import sop.testsuite.TestData;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PasswordHelperTest {

    @Test
    public void testAddBytesPassphraseWithTrailingWhitespace() throws IOException {
        OpenPGPKey k = PGPainless.getInstance().readKey().parseKey(TestData.PASSWORD_PROTECTED_KEY);
        MatchMakingSecretKeyRingProtector p = new MatchMakingSecretKeyRingProtector();
        PasswordHelper.addPassphrasePlusRemoveWhitespace((TestData.PASSWORD + " ").getBytes(StandardCharsets.UTF_8), p);
        p.addSecretKey(k);

        assertTrue(p.hasPassphraseFor(k.getKeyIdentifier()));
    }

    @Test
    public void testAddBytesPassphraseWithLeadingWhitespace() throws IOException {
        OpenPGPKey k = PGPainless.getInstance().readKey().parseKey(TestData.PASSWORD_PROTECTED_KEY);
        MatchMakingSecretKeyRingProtector p = new MatchMakingSecretKeyRingProtector();
        PasswordHelper.addPassphrasePlusRemoveWhitespace((" " + TestData.PASSWORD).getBytes(StandardCharsets.UTF_8), p);
        p.addSecretKey(k);

        assertTrue(p.hasPassphraseFor(k.getKeyIdentifier()));
    }

    @Test
    public void testAddNonUTF8Passphrase() throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        for (int i = 0xc0; i <= 0xdf; i++) {
            bOut.write(i);
            bOut.write(" ".getBytes());
        }
        byte[] nonUtf8 = bOut.toByteArray();
        MatchMakingSecretKeyRingProtector protector = new MatchMakingSecretKeyRingProtector();
        assertThrows(SOPGPException.PasswordNotHumanReadable.class, () ->
                PasswordHelper.addPassphrasePlusRemoveWhitespace(nonUtf8, protector));
    }
}
