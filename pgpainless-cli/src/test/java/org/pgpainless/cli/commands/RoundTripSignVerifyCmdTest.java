// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli.commands;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.text.ParseException;
import java.util.Date;

import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve;
import org.pgpainless.key.generation.type.xdh_legacy.XDHLegacySpec;
import org.pgpainless.key.info.KeyRingInfo;
import org.slf4j.LoggerFactory;
import sop.exception.SOPGPException;
import sop.util.UTCUtil;

public class RoundTripSignVerifyCmdTest extends CLITest {

    private final PGPainless api = PGPainless.getInstance();

    public RoundTripSignVerifyCmdTest() {
        super(LoggerFactory.getLogger(RoundTripSignVerifyCmdTest.class));
    }

    private static final String KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 9DA0 9423 C9F9 4BA4 CCA3  0951 099B 11BF 296A 373E\n" +
            "Comment: Sigmund <sigmund@pgpainless.org>\n" +
            "\n" +
            "lFgEY2vzkhYJKwYBBAHaRw8BAQdA+Z2OAFQf0k64Au7hIZfXh/ijclabddvwh7Nh\n" +
            "kedJ3ZUAAQCZy5p1cvQvRIWUopHwhnrD/oVAa1dNT/nA3cihQ5gkZBHPtCBTaWdt\n" +
            "dW5kIDxzaWdtdW5kQHBncGFpbmxlc3Mub3JnPoiPBBMWCgBBBQJja/OSCRAJmxG/\n" +
            "KWo3PhYhBJ2glCPJ+UukzKMJUQmbEb8pajc+Ap4BApsBBRYCAwEABAsJCAcFFQoJ\n" +
            "CAsCmQEAACM9AP9APloI2waD5gXsJqzenRVU4n/VmZUvcdUyhlbpab/0HQEAlaTw\n" +
            "ZvxVyaf8EMFSJOY+LcgacHaZDHRPA1nS3bIfKwycXQRja/OSEgorBgEEAZdVAQUB\n" +
            "AQdA1WL4QKgRxbvzW91ICM6PoICSNh2QHK6j0pIdN/cqXz0DAQgHAAD/bOk3WqbF\n" +
            "QAE8xxm0w/KDZzL1N0yPcBQ5z4XKmu77FCgQ04h1BBgWCgAdBQJja/OSAp4BApsM\n" +
            "BRYCAwEABAsJCAcFFQoJCAsACgkQCZsRvylqNz6rgQEAzoG6HnPCYi2i2c6/ufuy\n" +
            "pBkLby2u1JjD0CWSbrM4dZ0A/j/pI4a9b8LcrZcuY2QwHqsXPAJp8QtOOQN6gTvN\n" +
            "WcQNnFgEY2vzkhYJKwYBBAHaRw8BAQdAsxcDCvst/GbWxQvvOpChSvmbqWeuBgm3\n" +
            "1vRoujFVFcYAAP9Ww46yfWipb8OivTSX+PvgdUhEeVgxENpsyOQLLhQP/RFziNUE\n" +
            "GBYKAH0FAmNr85ICngECmwIFFgIDAQAECwkIBwUVCgkIC18gBBkWCgAGBQJja/OS\n" +
            "AAoJENqfQTmGIR3GtsMBAL+b1Zo5giQKJGEyx5aGwAz3AwtGiT6QDS9FH6HyM855\n" +
            "AP4uAXDiaNxYTugqnG471jYX/hhJqIROeDGrEIkkAp+qDwAKCRAJmxG/KWo3PhOX\n" +
            "AP45LPV6I4+D3h8etdiEA2DVvNcpRA8l4WkNcq4q8H1SjwD/c/rX3FCUIWLlAHoR\n" +
            "WxCFj+gDgqDNLzwoA4iNo1VMtQc=\n" +
            "=/Np6\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

    private static final String CERT = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 9DA0 9423 C9F9 4BA4 CCA3  0951 099B 11BF 296A 373E\n" +
            "Comment: Sigmund <sigmund@pgpainless.org>\n" +
            "\n" +
            "mDMEY2vzkhYJKwYBBAHaRw8BAQdA+Z2OAFQf0k64Au7hIZfXh/ijclabddvwh7Nh\n" +
            "kedJ3ZW0IFNpZ211bmQgPHNpZ211bmRAcGdwYWlubGVzcy5vcmc+iI8EExYKAEEF\n" +
            "AmNr85IJEAmbEb8pajc+FiEEnaCUI8n5S6TMowlRCZsRvylqNz4CngECmwEFFgID\n" +
            "AQAECwkIBwUVCgkICwKZAQAAIz0A/0A+WgjbBoPmBewmrN6dFVTif9WZlS9x1TKG\n" +
            "Vulpv/QdAQCVpPBm/FXJp/wQwVIk5j4tyBpwdpkMdE8DWdLdsh8rDLg4BGNr85IS\n" +
            "CisGAQQBl1UBBQEBB0DVYvhAqBHFu/Nb3UgIzo+ggJI2HZAcrqPSkh039ypfPQMB\n" +
            "CAeIdQQYFgoAHQUCY2vzkgKeAQKbDAUWAgMBAAQLCQgHBRUKCQgLAAoJEAmbEb8p\n" +
            "ajc+q4EBAM6Buh5zwmItotnOv7n7sqQZC28trtSYw9Alkm6zOHWdAP4/6SOGvW/C\n" +
            "3K2XLmNkMB6rFzwCafELTjkDeoE7zVnEDbgzBGNr85IWCSsGAQQB2kcPAQEHQLMX\n" +
            "Awr7Lfxm1sUL7zqQoUr5m6lnrgYJt9b0aLoxVRXGiNUEGBYKAH0FAmNr85ICngEC\n" +
            "mwIFFgIDAQAECwkIBwUVCgkIC18gBBkWCgAGBQJja/OSAAoJENqfQTmGIR3GtsMB\n" +
            "AL+b1Zo5giQKJGEyx5aGwAz3AwtGiT6QDS9FH6HyM855AP4uAXDiaNxYTugqnG47\n" +
            "1jYX/hhJqIROeDGrEIkkAp+qDwAKCRAJmxG/KWo3PhOXAP45LPV6I4+D3h8etdiE\n" +
            "A2DVvNcpRA8l4WkNcq4q8H1SjwD/c/rX3FCUIWLlAHoRWxCFj+gDgqDNLzwoA4iN\n" +
            "o1VMtQc=\n" +
            "=KuJ4\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";
    private static final String PLAINTEXT = "Hello, World!\n";
    private static final String BINARY_SIG = "-----BEGIN PGP SIGNATURE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "iHUEABYKACcFAmNr9BgJENqfQTmGIR3GFiEEREwQqwEe+EJMg/Cp2p9BOYYhHcYA\n" +
            "AKocAP48P2C3TU33T3Zy73clw0eBa1oW9pwxTGuFxhgOBzmoSwEArj0781GlpTB0\n" +
            "Vnr2PjPYEqzB+ZuOzOnGhsVGob4c3Ao=\n" +
            "=VWAZ\n" +
            "-----END PGP SIGNATURE-----";
    private static final String BINARY_SIG_VERIFICATION =
            "2022-11-09T18:40:24Z 444C10AB011EF8424C83F0A9DA9F413986211DC6 9DA09423C9F94BA4CCA30951099B11BF296A373E mode:binary\n";
    private static final String TEXT_SIG = "-----BEGIN PGP SIGNATURE-----\n" +
            "Version: PGPainless\n" +
            "\n" +
            "iHUEARYKACcFAmNr9E4JENqfQTmGIR3GFiEEREwQqwEe+EJMg/Cp2p9BOYYhHcYA\n" +
            "AG+CAQD1B3GAAlyxahSiGhvJv7YAI1m6qGcI7dIXcV7FkAFPSgEAlZ0UpCC8oGR+\n" +
            "hi/mQlex4z0hDWSA4abAjclPTJ+qkAI=\n" +
            "=s5xn\n" +
            "-----END PGP SIGNATURE-----";
    private static final String TEXT_SIG_VERIFICATION =
            "2022-11-09T18:41:18Z 444C10AB011EF8424C83F0A9DA9F413986211DC6 9DA09423C9F94BA4CCA30951099B11BF296A373E mode:text\n";
    private static final Date TEXT_SIG_CREATION;

    static {
        try {
            TEXT_SIG_CREATION = UTCUtil.parseUTCDate("2022-11-09T18:41:18Z");
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void createArmoredSignature() throws IOException {
        File keyFile = writeFile("key.asc", KEY);
        pipeStringToStdin(PLAINTEXT);
        ByteArrayOutputStream out = pipeStdoutToStream();
        assertSuccess(executeCommand("sign", "--as", "text", keyFile.getAbsolutePath()));
        assertTrue(out.toString().startsWith("-----BEGIN PGP SIGNATURE-----\n"));
    }

    @Test
    public void createUnarmoredSignature() throws IOException {
        File keyFile = writeFile("key.asc", KEY);
        pipeStringToStdin(PLAINTEXT);
        ByteArrayOutputStream out = pipeStdoutToStream();
        assertSuccess(executeCommand("sign", "--no-armor", keyFile.getAbsolutePath()));
        assertFalse(out.toString().startsWith("-----BEGIN PGP SIGNATURE-----\n"));
    }

    @Test
    public void unarmorArmoredSigAndVerify() throws IOException {
        File certFile = writeFile("cert.asc", CERT);

        pipeStringToStdin(BINARY_SIG);
        File unarmoredSigFile = pipeStdoutToFile("sig.pgp");
        assertSuccess(executeCommand("dearmor"));

        pipeStringToStdin(PLAINTEXT);
        ByteArrayOutputStream out = pipeStdoutToStream();
        assertSuccess(executeCommand("verify", unarmoredSigFile.getAbsolutePath(), certFile.getAbsolutePath()));

        assertEquals(BINARY_SIG_VERIFICATION, out.toString());
    }

    @Test
    public void testNotBefore() throws IOException {
        File cert = writeFile("cert.asc", CERT);
        File sigFile = writeFile("sig.asc", TEXT_SIG);
        Date plus1Minute = new Date(TEXT_SIG_CREATION.getTime() + 1000 * 60);

        pipeStringToStdin(PLAINTEXT);
        ByteArrayOutputStream out = pipeStdoutToStream();
        int exitCode = executeCommand("verify", sigFile.getAbsolutePath(), cert.getAbsolutePath(),
                "--not-before", UTCUtil.formatUTCDate(plus1Minute));

        assertEquals(SOPGPException.NoSignature.EXIT_CODE, exitCode);
        assertEquals(0, out.size());

        Date minus1Minute = new Date(TEXT_SIG_CREATION.getTime() - 1000 * 60);
        pipeStringToStdin(PLAINTEXT);
        out = pipeStdoutToStream();
        exitCode = executeCommand("verify", sigFile.getAbsolutePath(), cert.getAbsolutePath(),
                "--not-before", UTCUtil.formatUTCDate(minus1Minute));

        assertSuccess(exitCode);
        assertEquals(TEXT_SIG_VERIFICATION, out.toString());
    }

    @Test
    public void testNotAfter() throws IOException {
        File cert = writeFile("cert.asc", CERT);
        File sigFile = writeFile("sig.asc", TEXT_SIG);

        Date minus1Minute = new Date(TEXT_SIG_CREATION.getTime() - 1000 * 60);
        pipeStringToStdin(PLAINTEXT);
        ByteArrayOutputStream out = pipeStdoutToStream();
        int exitCode = executeCommand("verify", sigFile.getAbsolutePath(), cert.getAbsolutePath(),
                "--not-after", UTCUtil.formatUTCDate(minus1Minute));

        assertEquals(SOPGPException.NoSignature.EXIT_CODE, exitCode);
        assertEquals(0, out.size());

        Date plus1Minute = new Date(TEXT_SIG_CREATION.getTime() + 1000 * 60);
        pipeStringToStdin(PLAINTEXT);
        out = pipeStdoutToStream();
        exitCode = executeCommand("verify", sigFile.getAbsolutePath(), cert.getAbsolutePath(),
                "--not-after", UTCUtil.formatUTCDate(plus1Minute));

        assertSuccess(exitCode);
        assertEquals(TEXT_SIG_VERIFICATION, out.toString());
    }

    @Test
    public void testSignWithIncapableKey()
            throws IOException {
        OpenPGPKey secretKeys = api.buildKey()
                .addUserId("Cannot Sign <cannot@sign.key>")
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.CERTIFY_OTHER))
                .addSubkey(KeySpec.getBuilder(KeyType.XDH_LEGACY(XDHLegacySpec._X25519), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE))
                .build();

        File keyFile = writeFile("key.pgp", secretKeys.getEncoded());

        pipeStringToStdin("Hello, World!\n");
        ByteArrayOutputStream out = pipeStdoutToStream();
        int exitCode = executeCommand("sign", keyFile.getAbsolutePath());

        assertEquals(SOPGPException.KeyCannotSign.EXIT_CODE, exitCode);
        assertEquals(0, out.size());
    }

    @Test
    public void testSignatureCreationAndVerification()
            throws IOException {
        // Create key and cert
        File aliceKeyFile = pipeStdoutToFile("alice.key");
        assertSuccess(executeCommand("generate-key", "Alice <alice@pgpainless.org>"));
        File aliceCertFile = pipeStdoutToFile("alice.cert");
        pipeFileToStdin(aliceKeyFile);
        assertSuccess(executeCommand("extract-cert"));

        File micalgOut = nonExistentFile("micalg");
        String msg = "If privacy is outlawed, only outlaws will have privacy.\n";
        File dataFile = writeFile("data", msg);

        // sign data
        File sigFile = pipeStdoutToFile("sig.asc");
        pipeFileToStdin(dataFile);
        assertSuccess(executeCommand("sign",
                "--armor",
                "--as", "binary",
                "--micalg-out", micalgOut.getAbsolutePath(),
                aliceKeyFile.getAbsolutePath()));

        // verify test data signature
        pipeFileToStdin(dataFile);
        ByteArrayOutputStream verificationsOut = pipeStdoutToStream();
        assertSuccess(executeCommand("verify", sigFile.getAbsolutePath(), aliceCertFile.getAbsolutePath()));

        // Test verification output

        OpenPGPCertificate cert = api.readKey().parseCertificate(readBytesFromFile(aliceCertFile));
        KeyRingInfo info = api.inspect(cert);

        // [date] [signing-key-fp] [primary-key-fp] signed by [key.pub]
        String verification = verificationsOut.toString();
        String[] split = verification.split(" ");
        OpenPgpV4Fingerprint primaryKeyFingerprint = new OpenPgpV4Fingerprint(cert);
        OpenPgpV4Fingerprint signingKeyFingerprint = new OpenPgpV4Fingerprint(info.getSigningSubkeys().get(0).getPGPPublicKey());
        assertEquals(signingKeyFingerprint.toString(), split[1].trim(), verification);
        assertEquals(primaryKeyFingerprint.toString(), split[2].trim());

        // Test micalg output
        String content = readStringFromFile(micalgOut);
        assertEquals("pgp-sha512", content);
    }

    private static final String PROTECTED_KEY = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Version: PGPainless\n" +
            "Comment: 738E EAB2 503D 322D 613A  C42A B18E 8BF8 884F C050\n" +
            "Comment: Axel <axel@pgpainless.org>\n" +
            "\n" +
            "lIYEY2v6aRYJKwYBBAHaRw8BAQdA3PXtH19zYpVQ9zTU3zlY+iXUptelAO3z4vK/\n" +
            "M2FkmrP+CQMCYgVa6K+InVJguITSDIA+HQ6vhOZ5Dbanqx7GFbJbJLD2fWrxhTSr\n" +
            "BUWGaUWTqN647auD/kUI8phH1cedVL6CzVR+YWvaWj9zZHr/CYXLobQaQXhlbCA8\n" +
            "YXhlbEBwZ3BhaW5sZXNzLm9yZz6IjwQTFgoAQQUCY2v6aQkQsY6L+IhPwFAWIQRz\n" +
            "juqyUD0yLWE6xCqxjov4iE/AUAKeAQKbAQUWAgMBAAQLCQgHBRUKCQgLApkBAACq\n" +
            "zgEAkxB+dUI7Jjcg5zRvT1EfE9DKCI1qTsxOAU/ZXLcSXLkBAJtWRsyptetZvjzB\n" +
            "Ze2A7ArOl4q+IvKvun/d783YyRMInIsEY2v6aRIKKwYBBAGXVQEFAQEHQPFmlZ+o\n" +
            "jCGEo2X0474vJfRG7blctuZXmCbC0sLO7MgzAwEIB/4JAwJiBVror4idUmDFhBq4\n" +
            "lEhJxjCVc6aSD6+EWRT3YdplqCmNdynnrPombUFst6LfJFzns3H3d0rCeXHfQr93\n" +
            "GrHTLkHfW8G3x0PJJPiqFkBviHUEGBYKAB0FAmNr+mkCngECmwwFFgIDAQAECwkI\n" +
            "BwUVCgkICwAKCRCxjov4iE/AUNC2AP9WDx4lHt9oYFLSrM8vMLRFI31U8TkYrtCe\n" +
            "pYICE76cIAEA5+wEbtE5vQrLxOqIRueVVdzwK9kTeMvSIQfc9PNoyQKchgRja/pp\n" +
            "FgkrBgEEAdpHDwEBB0CyAEVlCUbFr3dBBG3MQ84hjCPfYqSx9kYsTN8j5Og6uP4J\n" +
            "AwJiBVror4idUmCIFuAYXia0YpEhEpB/Lrn/D6/WAUPEgZjNLMvJzL//EmhkWfEa\n" +
            "OfQz/fslj1erWNjLKNiW5C/TvGapDfjbn596AkNlcd1JiNUEGBYKAH0FAmNr+mkC\n" +
            "ngECmwIFFgIDAQAECwkIBwUVCgkIC18gBBkWCgAGBQJja/ppAAoJELRgil1uCuQj\n" +
            "VUYBAJecbedwwqWQITVqucEBIraTRoc6ZGkN8jytDp8z9CsBAQDrb/W/J/kze6ln\n" +
            "nRyJSriWF3SjcKOGIRkUslmdJEPPCQAKCRCxjov4iE/AUAvbAQDBBgQFG8acTT5L\n" +
            "cyIi1Ix9/XBG7G23SSs6l7Beap8M+wEAmK13NYuq7Mv/mct8iIKZbBFH9aAiY+nX\n" +
            "3Uct4Q5f0w0=\n" +
            "=K65R\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";
    private static final String PASSPHRASE = "orange";
    private static final String SIGNING_KEY = "9846F3606EE875FB77EC8808B4608A5D6E0AE423 738EEAB2503D322D613AC42AB18E8BF8884FC050";

    @Test
    public void signWithProtectedKey_missingPassphraseFails() throws IOException {
        File key = writeFile("key.asc", PROTECTED_KEY);
        pipeStringToStdin(PLAINTEXT);
        ByteArrayOutputStream out = pipeStdoutToStream();
        int exitCode = executeCommand("sign", key.getAbsolutePath());
        assertEquals(SOPGPException.KeyIsProtected.EXIT_CODE, exitCode);
        assertEquals(0, out.size());
    }

    @Test
    public void signWithProtectedKey_wrongPassphraseFails() throws IOException {
        File password = writeFile("password", "blue");
        File key = writeFile("key.asc", PROTECTED_KEY);
        pipeStringToStdin(PLAINTEXT);
        ByteArrayOutputStream out = pipeStdoutToStream();
        int exitCode = executeCommand("sign", key.getAbsolutePath(),
                "--with-key-password", password.getAbsolutePath());
        assertEquals(SOPGPException.KeyIsProtected.EXIT_CODE, exitCode);
        assertEquals(0, out.size());
    }

    @Test
    public void signWithProtectedKey() throws IOException {
        File password = writeFile("password", PASSPHRASE);
        File key = writeFile("key.asc", PROTECTED_KEY);
        pipeStringToStdin(PROTECTED_KEY);
        File cert = pipeStdoutToFile("cert.asc");
        assertSuccess(executeCommand("extract-cert"));

        pipeStringToStdin(PLAINTEXT);
        File sigFile = pipeStdoutToFile("sig.asc");
        assertSuccess(executeCommand("sign", key.getAbsolutePath(),
                "--with-key-password", password.getAbsolutePath()));

        pipeStringToStdin(PLAINTEXT);
        ByteArrayOutputStream verificationOut = pipeStdoutToStream();
        assertSuccess(executeCommand("verify", sigFile.getAbsolutePath(), cert.getAbsolutePath()));
        assertTrue(verificationOut.toString().contains(SIGNING_KEY));
    }

}
