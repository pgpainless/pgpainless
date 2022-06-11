// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli.commands;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import com.ginsberg.junit.exit.FailOnSystemExit;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.cli.PGPainlessCLI;
import org.pgpainless.key.info.KeyRingInfo;

public class ExtractCertCmdTest {

    @Test
    @FailOnSystemExit
    public void testExtractCert() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .simpleEcKeyRing("Juliet Capulet <juliet@capulet.lit>");
        ByteArrayInputStream inputStream = new ByteArrayInputStream(secretKeys.getEncoded());
        System.setIn(inputStream);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));

        PGPainlessCLI.execute("extract-cert");
        PGPPublicKeyRing publicKeys = PGPainless.readKeyRing().publicKeyRing(out.toByteArray());
        KeyRingInfo info = PGPainless.inspectKeyRing(publicKeys);
        assertFalse(info.isSecretKey());
        assertTrue(info.isUserIdValid("Juliet Capulet <juliet@capulet.lit>"));
    }
}
