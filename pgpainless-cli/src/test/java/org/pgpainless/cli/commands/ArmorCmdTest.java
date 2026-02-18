// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli.commands;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.slf4j.LoggerFactory;

public class ArmorCmdTest extends CLITest {

    private final PGPainless api = PGPainless.getInstance();

    public ArmorCmdTest() {
        super(LoggerFactory.getLogger(ArmorCmdTest.class));
    }

    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
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
    public void armorSecretKey() throws IOException {
        OpenPGPKey key = api.readKey().parseKey(KEY);
        byte[] binary = key.getEncoded();

        pipeBytesToStdin(binary);
        ByteArrayOutputStream armorOut = pipeStdoutToStream();
        assertSuccess(executeCommand("armor"));

        OpenPGPKey armored = api.readKey().parseKey(armorOut.toString());
        assertArrayEquals(binary, armored.getEncoded());
    }

    @Test
    public void armorPublicKey() throws IOException {
        OpenPGPKey secretKey = api.readKey().parseKey(KEY);
        OpenPGPCertificate publicKey = secretKey.toCertificate();
        byte[] bytes = publicKey.getEncoded();

        pipeBytesToStdin(bytes);
        ByteArrayOutputStream armorOut = pipeStdoutToStream();
        assertSuccess(executeCommand("armor"));

        OpenPGPCertificate armored = api.readKey().parseCertificate(armorOut.toString());
        assertArrayEquals(publicKey.getEncoded(), armored.getEncoded());
    }

    @Test
    public void armorMessage() throws IOException {
        String message = "Hello, World!\n";
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        OutputStream litOut = litGen.open(bOut, PGPLiteralDataGenerator.UTF8, "", PGPLiteralDataGenerator.NOW, new byte[512]);
        litOut.write(message.getBytes(StandardCharsets.UTF_8));
        litOut.close();

        pipeBytesToStdin(bOut.toByteArray());
        ByteArrayOutputStream armorOut = pipeStdoutToStream();
        assertSuccess(executeCommand("armor"));

        String armored = armorOut.toString();
        assertTrue(armored.startsWith("-----BEGIN PGP MESSAGE-----\n"));
    }

    @Test
    public void armorAlreadyArmoredDataIsIdempotent() throws IOException {
        pipeStringToStdin(KEY);
        ByteArrayOutputStream armorOut = pipeStdoutToStream();
        assertSuccess(executeCommand("armor"));

        String armored = armorOut.toString();
        assertEquals(KEY, armored);
    }
}
