// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli.commands;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.pgpainless.cli.TestUtils;
import org.slf4j.LoggerFactory;
import sop.exception.SOPGPException;

public class InlineDetachCmdTest extends CLITest {

    private static final String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: BCPG v1.64\n" +
            "\n" +
            "mFIEXhtfCBMIKoZIzj0DAQcCAwTGSFMBUOSLusXS8hdNHbdK3gN8hS7jd4ky7Czl\n" +
            "mSti+oVyRJUwQAFZJ1NMsg1H8flSJP1/9YbHd9FBU4bHKGKPtBE8ZW1pbEBlbWFp\n" +
            "bC51c2VyPoh1BBMTCgAdBQJeG18IAhsjBRYCAwEABAsJCAcFFQoJCAsCHgEACgkQ\n" +
            "VzbmkxrPNwz8rAD/S/VCQc5NJLArgTDkgrt3Q573HiYfrIQo1uk3dwV15WIBAMiq\n" +
            "oDmRMb8jzOBv6FGW4P5WAubPdnAvDD7XmArD+TSeuFYEXhtfCBIIKoZIzj0DAQcC\n" +
            "AwTgWDWmHJLQUQ35Qg/rINmUhkUhj1E4O5t6Y2PipbqlGfDufLmIKnX40BoJPS4G\n" +
            "HW7U0QXfwSaTXa1BAaNsMUomAwEIB4h1BBgTCgAdBQJeG18IAhsMBRYCAwEABAsJ\n" +
            "CAcFFQoJCAsCHgEACgkQVzbmkxrPNwxOcwEA19Fnhw7XwpQoT61Fqg54vroAwTZ3\n" +
            "T5A+LOdevAtzNOUA/RWeKfOGk6D+vKYRNpMJyqsHi/vBeKwXoeN0n6HuExVF\n" +
            "=a1W7\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

    private static final String CLEAR_SIGNED_MESSAGE = "-----BEGIN PGP SIGNED MESSAGE-----\n" +
            "Hash: SHA512\n" +
            "\n" +
            "Ah, Juliet, if the measure of thy joy\n" +
            "Be heaped like mine, and that thy skill be more\n" +
            "To blazon it, then sweeten with thy breath\n" +
            "This neighbor air, and let rich music’s tongue\n" +
            "Unfold the imagined happiness that both\n" +
            "Receive in either by this dear encounter.\n" +
            "-----BEGIN PGP SIGNATURE-----\n" +
            "\n" +
            "iHUEARMKAB0WIQRPZlxNwsRmC8ZCXkFXNuaTGs83DAUCYJ/x5gAKCRBXNuaTGs83\n" +
            "DFRwAP9/4wMvV3WcX59Clo7mkRce6iwW3VBdiN+yMu3tjmHB2wD/RfE28Q1v4+eo\n" +
            "ySNgbyvqYYsNr0fnBwaG3aaj+u5ExiE=\n" +
            "=Z2SO\n" +
            "-----END PGP SIGNATURE-----";

    private static final String CLEAR_SIGNED_SIGNATURE = "-----BEGIN PGP SIGNATURE-----\n" +
            "\n" +
            "iHUEARMKAB0WIQRPZlxNwsRmC8ZCXkFXNuaTGs83DAUCYJ/x5gAKCRBXNuaTGs83\n" +
            "DFRwAP9/4wMvV3WcX59Clo7mkRce6iwW3VBdiN+yMu3tjmHB2wD/RfE28Q1v4+eo\n" +
            "ySNgbyvqYYsNr0fnBwaG3aaj+u5ExiE=\n" +
            "=Z2SO\n" +
            "-----END PGP SIGNATURE-----";

    private static final String CLEAR_SIGNED_BODY = "Ah, Juliet, if the measure of thy joy\n" +
            "Be heaped like mine, and that thy skill be more\n" +
            "To blazon it, then sweeten with thy breath\n" +
            "This neighbor air, and let rich music’s tongue\n" +
            "Unfold the imagined happiness that both\n" +
            "Receive in either by this dear encounter.";

    public InlineDetachCmdTest() {
        super(LoggerFactory.getLogger(InlineDetachCmdTest.class));
    }

    @Test
    public void detachInbandSignatureAndMessage() throws IOException {
        pipeStringToStdin(CLEAR_SIGNED_MESSAGE);
        ByteArrayOutputStream msgOut = pipeStdoutToStream();
        File sigFile = nonExistentFile("sig.out");

        assertSuccess(executeCommand("inline-detach", "--signatures-out", sigFile.getAbsolutePath()));
        assertTrue(sigFile.exists(), "Signature file must have been written.");

        // Test equality with expected values
        assertEquals(CLEAR_SIGNED_BODY, msgOut.toString());
        String sig = readStringFromFile(sigFile);
        TestUtils.assertSignatureIsArmored(sig.getBytes());
        TestUtils.assertSignatureEquals(CLEAR_SIGNED_SIGNATURE, sig);

        // Check if produced signature still checks out
        File certFile = writeFile("cert.asc", CERT);
        pipeStringToStdin(msgOut.toString());
        ByteArrayOutputStream verifyOut = pipeStdoutToStream();
        assertSuccess(executeCommand("verify", sigFile.getAbsolutePath(), certFile.getAbsolutePath()));
        assertEquals("2021-05-15T16:08:06Z 4F665C4DC2C4660BC6425E415736E6931ACF370C 4F665C4DC2C4660BC6425E415736E6931ACF370C\n",
                verifyOut.toString());
    }

    @Test
    public void detachInbandSignatureAndMessageNoArmor() throws IOException {
        pipeStringToStdin(CLEAR_SIGNED_MESSAGE);
        ByteArrayOutputStream msgOut = pipeStdoutToStream();
        File sigFile = nonExistentFile("sig.out");

        assertSuccess(executeCommand("inline-detach", "--signatures-out", sigFile.getAbsolutePath(), "--no-armor"));

        // Test equality with expected values
        assertEquals(CLEAR_SIGNED_BODY, msgOut.toString());
        assertTrue(sigFile.exists(), "Signature file must have been written.");
        byte[] sig = readBytesFromFile(sigFile);

        TestUtils.assertSignatureIsNotArmored(sig);
        TestUtils.assertSignatureEquals(CLEAR_SIGNED_SIGNATURE.getBytes(StandardCharsets.UTF_8), sig);

        // Check if produced signature still checks out
        pipeBytesToStdin(msgOut.toByteArray());
        ByteArrayOutputStream verifyOut = pipeStdoutToStream();
        File certFile = writeFile("cert.asc", CERT);
        assertSuccess(executeCommand("verify", sigFile.getAbsolutePath(), certFile.getAbsolutePath()));
        assertEquals("2021-05-15T16:08:06Z 4F665C4DC2C4660BC6425E415736E6931ACF370C 4F665C4DC2C4660BC6425E415736E6931ACF370C\n",
                verifyOut.toString());
    }

    @Test
    public void existingSignatureOutCausesException() throws IOException {
        pipeStringToStdin(CLEAR_SIGNED_MESSAGE);
        ByteArrayOutputStream msgOut = pipeStdoutToStream();
        File existingSigFile = writeFile("sig.asc", CLEAR_SIGNED_SIGNATURE);
        int exit = executeCommand("inline-detach", "--signatures-out", existingSigFile.getAbsolutePath());
        assertEquals(SOPGPException.OutputExists.EXIT_CODE, exit);
        assertEquals(0, msgOut.size());
    }

}
