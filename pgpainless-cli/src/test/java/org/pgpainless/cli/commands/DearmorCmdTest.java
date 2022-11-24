// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli.commands;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.slf4j.LoggerFactory;
import sop.exception.SOPGPException;

public class DearmorCmdTest extends CLITest {

    public DearmorCmdTest() {
        super(LoggerFactory.getLogger(DearmorCmdTest.class));
    }

    private static final String key = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 62E9 DDA4 F20F 8341 D2BC  4B4C 8B07 5177 01F9 534C\n" +
            "Comment: alice@pgpainless.org\n" +
            "\n" +
            "lFgEY2vOkhYJKwYBBAHaRw8BAQdAqGOtLd1tKnuwaYYcdr2/7C0cPiCCggRMKG+W\n" +
            "t32QQdEAAP9VaBzjk/AaAqyykZnQHmS1HByEvRLv5/4yJMSr22451BFjtBRhbGlj\n" +
            "ZUBwZ3BhaW5sZXNzLm9yZ4iOBBMWCgBBBQJja86SCRCLB1F3AflTTBYhBGLp3aTy\n" +
            "D4NB0rxLTIsHUXcB+VNMAp4BApsBBRYCAwEABAsJCAcFFQoJCAsCmQEAACZhAP4s\n" +
            "8hn/RBDvyLvGROOd15EYATnWlgyi+b5WXP6cELalJwD1FZy3RROhfNtZWcJPS43f\n" +
            "G03pYNyb0NXoitIMAaXEB5xdBGNrzpISCisGAQQBl1UBBQEBB0CqCcYethOynfni\n" +
            "8uRO+r/cZWp9hCLy8pRIExKqzcyEFAMBCAcAAP9sRRLoZkLpDaTNNrtIBovXu2AN\n" +
            "hL8keUMWtVcuEHnkQA6iiHUEGBYKAB0FAmNrzpICngECmwwFFgIDAQAECwkIBwUV\n" +
            "CgkICwAKCRCLB1F3AflTTBVpAP491etrjqCMWx2bBaw3K1vP0Mix6U0vF3J4kP9U\n" +
            "eZm6owEA4kX9VAGESvLgIc7CEiswmxdWjxnLQyCRtWXfjgFmYQucWARja86SFgkr\n" +
            "BgEEAdpHDwEBB0DBslhDpWC6CV3xJUSo071NSO5Cf4fgOwOj+QHs8mpFbwABAPkQ\n" +
            "ioSydYiMi04LyfPohyrhhcdJDHallQg+jYHHUb2pEJCI1QQYFgoAfQUCY2vOkgKe\n" +
            "AQKbAgUWAgMBAAQLCQgHBRUKCQgLXyAEGRYKAAYFAmNrzpIACgkQiHlkvEXh+f1e\n" +
            "ywEA9A2GLU9LxCJxZf2X4qcZY//YJDChIZHPnY0Vaek1DsMBAN1YILrH2rxQeCXj\n" +
            "m4bUKfJIRrGt6ZJscwORgNI1dFQFAAoJEIsHUXcB+VNMK3gA/3vvPm57JsHA860w\n" +
            "lB4D1II71oFNL8TFnJqTAvpSKe1AAP49S4mKB4PE0ElcDo7n+nEYt6ba8IMRDlMo\n" +
            "rsH85mUgCw==\n" +
            "=EMKf\n" +
            "-----END PGP PRIVATE KEY BLOCK-----\n";

    @Test
    public void dearmorSecretKey() throws IOException {
        PGPSecretKeyRing secretKey = PGPainless.readKeyRing().secretKeyRing(key);

        pipeStringToStdin(key);
        ByteArrayOutputStream dearmored = pipeStdoutToStream();
        assertSuccess(executeCommand("dearmor"));

        assertArrayEquals(secretKey.getEncoded(), dearmored.toByteArray());
    }

    @Test
    public void dearmorBrokenArmoredKeyFails() throws IOException {
        // contains a "-"
        String invalidBase64 = "lFgEY2vOkhYJKwYBBAHaRw8BAQdAqGOtLd1tKnuwaYYcdr2/7C0cPiCCggRMKG+Wt32QQdEAAP9VaBzjk/AaAqyykZnQHmS1HByEvRLv5/4yJMSr22451BFjtBRhbGljZUBwZ3BhaW5sZXNzLm9yZ4iOBBMWCgBBBQJja86SCRCLB1F3AflTTBYhBGLp3aTyD4NB0rxLT-IsHUXcB+VNMAp4BApsBBRYCAwEABAsJCAcFFQoJCAsCmQEAACZhAP4s8hn/RBDvyLvGROOd15EYATnWlgyi+b5WXP6cELalJwD1FZy3RROhfNtZWcJPS43fG03pYNyb0NXoitIMAaXEB5xdBGNrzpISCisGAQQBl1UBBQEBB0CqCcYethOynfni8uRO+r/cZWp9hCLy8pRIExKqzcyEFAMBCAcAAP9sRRLoZkLpDaTNNrtIBovXu2ANhL8keUMWtVcuEHnkQA6iiHUEGBYKAB0FAmNrzpICngECmwwFFgIDAQAECwkIBwUVCgkICwAKCRCLB1F3AflTTBVpAP491etrjqCMWx2bBaw3K1vP0Mix6U0vF3J4kP9UeZm6owEA4kX9VAGESvLgIc7CEiswmxdWjxnLQyCRtWXfjgFmYQucWARja86SFgkrBgEEAdpHDwEBB0DBslhDpWC6CV3xJUSo071NSO5Cf4fgOwOj+QHs8mpFbwABAPkQioSydYiMi04LyfPohyrhhcdJDHallQg+jYHHUb2pEJCI1QQYFgoAfQUCY2vOkgKeAQKbAgUWAgMBAAQLCQgHBRUKCQgLXyAEGRYKAAYFAmNrzpIACgkQiHlkvEXh+f1eywEA9A2GLU9LxCJxZf2X4qcZY//YJDChIZHPnY0Vaek1DsMBAN1YILrH2rxQeCXjm4bUKfJIRrGt6ZJscwORgNI1dFQFAAoJEIsHUXcB+VNMK3gA/3vvPm57JsHA860wlB4D1II71oFNL8TFnJqTAvpSKe1AAP49S4mKB4PE0ElcDo7n+nEYt6ba8IMRDlMorsH85mUgCw==";
        pipeStringToStdin(invalidBase64);
        ByteArrayOutputStream out = pipeStdoutToStream();
        int exitCode = executeCommand("dearmor");

        assertEquals(SOPGPException.BadData.EXIT_CODE, exitCode);
        assertEquals(0, out.size());
    }

    @Test
    public void dearmorCertificate() throws IOException {
        PGPSecretKeyRing secretKey = PGPainless.readKeyRing().secretKeyRing(key);
        PGPPublicKeyRing certificate = PGPainless.extractCertificate(secretKey);
        String armoredCert = PGPainless.asciiArmor(certificate);

        pipeStringToStdin(armoredCert);
        ByteArrayOutputStream out = pipeStdoutToStream();
        assertSuccess(executeCommand("dearmor"));

        assertArrayEquals(certificate.getEncoded(), out.toByteArray());
    }

    @Test
    public void dearmorMessage() throws IOException {
        String armored = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: BCPG v1.69\n" +
                "\n" +
                "SGVsbG8sIFdvcmxkCg==\n" +
                "=fkLo\n" +
                "-----END PGP MESSAGE-----";

        pipeStringToStdin(armored);
        ByteArrayOutputStream out = pipeStdoutToStream();
        assertSuccess(executeCommand("dearmor"));

        assertEquals("Hello, World\n", out.toString());
    }

    @Test
    public void dearmorGarbageEmitsEmpty() throws IOException {
        String noArmoredData = "This is not armored.";
        pipeStringToStdin(noArmoredData);
        ByteArrayOutputStream out = pipeStdoutToStream();
        assertSuccess(executeCommand("dearmor"));
        assertTrue(out.toString().isEmpty());
    }

}
