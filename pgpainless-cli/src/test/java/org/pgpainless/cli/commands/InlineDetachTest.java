// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli.commands;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import com.ginsberg.junit.exit.ExpectSystemExitWithStatus;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pgpainless.cli.PGPainlessCLI;
import org.pgpainless.cli.TestUtils;
import sop.exception.SOPGPException;

public class InlineDetachTest {

    private PrintStream originalSout;
    private static File tempDir;
    private static File certFile;

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

    @BeforeAll
    public static void createTempDir() throws IOException {
        tempDir = TestUtils.createTempDirectory();

        certFile = new File(tempDir, "cert.asc");
        assertTrue(certFile.createNewFile());
        try (FileOutputStream out = new FileOutputStream(certFile)) {
            ByteArrayInputStream in = new ByteArrayInputStream(CERT.getBytes(StandardCharsets.UTF_8));
            Streams.pipeAll(in, out);
        }
    }

    @BeforeEach
    public void saveSout() {
        this.originalSout = System.out;
    }

    @AfterEach
    public void restoreSout() {
        System.setOut(originalSout);
    }

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

    @Test
    public void detachInbandSignatureAndMessage() throws IOException {
        // Clearsigned In
        ByteArrayInputStream clearSignedIn = new ByteArrayInputStream(CLEAR_SIGNED_MESSAGE.getBytes(StandardCharsets.UTF_8));
        System.setIn(clearSignedIn);

        // Plaintext Out
        ByteArrayOutputStream msgOut = new ByteArrayOutputStream();
        System.setOut(new PrintStream(msgOut));

        // Detach
        File tempSigFile = new File(tempDir, "sig.out");
        PGPainlessCLI.main(new String[] {"inline-detach", "--signatures-out=" + tempSigFile.getAbsolutePath()});

        // Test equality with expected values
        assertEquals(CLEAR_SIGNED_BODY, msgOut.toString());
        try (FileInputStream sigIn = new FileInputStream(tempSigFile)) {
            ByteArrayOutputStream sigBytes = new ByteArrayOutputStream();
            Streams.pipeAll(sigIn, sigBytes);
            String sig = sigBytes.toString();
            TestUtils.assertSignatureIsArmored(sigBytes.toByteArray());
            TestUtils.assertSignatureEquals(CLEAR_SIGNED_SIGNATURE, sig);
        } catch (FileNotFoundException e) {
            fail("Signature File must have been written.", e);
        }

        // Check if produced signature still checks out
        System.setIn(new ByteArrayInputStream(msgOut.toByteArray()));
        ByteArrayOutputStream verifyOut = new ByteArrayOutputStream();
        System.setOut(new PrintStream(verifyOut));
        PGPainlessCLI.main(new String[] {"verify", tempSigFile.getAbsolutePath(), certFile.getAbsolutePath()});

        assertEquals("2021-05-15T16:08:06Z 4F665C4DC2C4660BC6425E415736E6931ACF370C 4F665C4DC2C4660BC6425E415736E6931ACF370C\n", verifyOut.toString());
    }

    @Test
    public void detachInbandSignatureAndMessageNoArmor() throws IOException {
        // Clearsigned In
        ByteArrayInputStream clearSignedIn = new ByteArrayInputStream(CLEAR_SIGNED_MESSAGE.getBytes(StandardCharsets.UTF_8));
        System.setIn(clearSignedIn);

        // Plaintext Out
        ByteArrayOutputStream msgOut = new ByteArrayOutputStream();
        System.setOut(new PrintStream(msgOut));

        // Detach
        File tempSigFile = new File(tempDir, "sig.asc");
        PGPainlessCLI.main(new String[] {"inline-detach", "--signatures-out=" + tempSigFile.getAbsolutePath(), "--no-armor"});

        // Test equality with expected values
        assertEquals(CLEAR_SIGNED_BODY, msgOut.toString());
        try (FileInputStream sigIn = new FileInputStream(tempSigFile)) {
            ByteArrayOutputStream sigBytes = new ByteArrayOutputStream();
            Streams.pipeAll(sigIn, sigBytes);
            byte[] sig = sigBytes.toByteArray();
            TestUtils.assertSignatureIsNotArmored(sig);
            TestUtils.assertSignatureEquals(CLEAR_SIGNED_SIGNATURE.getBytes(StandardCharsets.UTF_8), sig);
        } catch (FileNotFoundException e) {
            fail("Signature File must have been written.", e);
        }

        // Check if produced signature still checks out
        System.setIn(new ByteArrayInputStream(msgOut.toByteArray()));
        ByteArrayOutputStream verifyOut = new ByteArrayOutputStream();
        System.setOut(new PrintStream(verifyOut));
        PGPainlessCLI.main(new String[] {"verify", tempSigFile.getAbsolutePath(), certFile.getAbsolutePath()});

        assertEquals("2021-05-15T16:08:06Z 4F665C4DC2C4660BC6425E415736E6931ACF370C 4F665C4DC2C4660BC6425E415736E6931ACF370C\n", verifyOut.toString());
    }

    @Test
    @ExpectSystemExitWithStatus(SOPGPException.OutputExists.EXIT_CODE)
    public void existingSignatureOutCausesException() throws IOException {
        // Clearsigned In
        ByteArrayInputStream clearSignedIn = new ByteArrayInputStream(CLEAR_SIGNED_MESSAGE.getBytes(StandardCharsets.UTF_8));
        System.setIn(clearSignedIn);

        // Plaintext Out
        ByteArrayOutputStream msgOut = new ByteArrayOutputStream();
        System.setOut(new PrintStream(msgOut));

        // Detach
        File existingSigFile = new File(tempDir, "sig.existing");
        assertTrue(existingSigFile.createNewFile());
        PGPainlessCLI.main(new String[] {"inline-detach", "--signatures-out=" + existingSigFile.getAbsolutePath()});
    }

}
