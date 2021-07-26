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
package org.pgpainless.cli.commands;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import com.ginsberg.junit.exit.FailOnSystemExit;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.cli.PGPainlessCLI;
import org.pgpainless.cli.TestUtils;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.util.StreamUtil;

public class SignVerifyTest {

    private static File tempDir;
    private static PrintStream originalSout;

    private final String data = "If privacy is outlawed, only outlaws will have privacy.\n";

    @BeforeAll
    public static void prepare() throws IOException {
        tempDir = TestUtils.createTempDirectory();
    }

    @Test
    @FailOnSystemExit
    public void testSignatureCreationAndVerification() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        originalSout = System.out;
        InputStream originalIn = System.in;

        // Write alice key to disc
        File aliceKeyFile = new File(tempDir, "alice.key");
        assertTrue(aliceKeyFile.createNewFile());
        PGPSecretKeyRing aliceKeys = PGPainless.generateKeyRing()
                .modernKeyRing("alice", null);
        OutputStream aliceKeyOut = new FileOutputStream(aliceKeyFile);
        StreamUtil.pipeAll(new ByteArrayInputStream(aliceKeys.getEncoded()), aliceKeyOut);
        aliceKeyOut.close();

        // Write alice pub key to disc
        File aliceCertFile = new File(tempDir, "alice.pub");
        assertTrue(aliceCertFile.createNewFile());
        PGPPublicKeyRing alicePub = KeyRingUtils.publicKeyRingFrom(aliceKeys);
        OutputStream aliceCertOut = new FileOutputStream(aliceCertFile);
        StreamUtil.pipeAll(new ByteArrayInputStream(alicePub.getEncoded()), aliceCertOut);
        aliceCertOut.close();

        // Write test data to disc
        File dataFile = new File(tempDir, "data");
        assertTrue(dataFile.createNewFile());
        FileOutputStream dataOut = new FileOutputStream(dataFile);
        StreamUtil.pipeAll(new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8)), dataOut);
        dataOut.close();

        // Sign test data
        FileInputStream dataIn = new FileInputStream(dataFile);
        System.setIn(dataIn);
        File sigFile = new File(tempDir, "sig.asc");
        assertTrue(sigFile.createNewFile());
        FileOutputStream sigOut = new FileOutputStream(sigFile);
        System.setOut(new PrintStream(sigOut));
        PGPainlessCLI.execute("sign", "--armor", aliceKeyFile.getAbsolutePath());
        sigOut.close();

        // verify test data signature
        ByteArrayOutputStream verifyOut = new ByteArrayOutputStream();
        System.setOut(new PrintStream(verifyOut));
        dataIn = new FileInputStream(dataFile);
        System.setIn(dataIn);
        PGPainlessCLI.execute("verify", sigFile.getAbsolutePath(), aliceCertFile.getAbsolutePath());
        dataIn.close();

        // Test verification output

        // [date] [signing-key-fp] [primary-key-fp] signed by [key.pub]
        String verification = verifyOut.toString();
        String[] split = verification.split(" ");
        OpenPgpV4Fingerprint primaryKeyFingerprint = new OpenPgpV4Fingerprint(aliceKeys);
        OpenPgpV4Fingerprint signingKeyFingerprint = new OpenPgpV4Fingerprint(new KeyRingInfo(alicePub, new Date()).getSigningSubkeys().get(0));
        assertEquals(signingKeyFingerprint.toString(), split[1].trim());
        assertEquals(primaryKeyFingerprint.toString(), split[2].trim());

        System.setIn(originalIn);
    }

    @AfterAll
    public static void after() {
        System.setOut(originalSout);
        // CHECKSTYLE:OFF
        System.out.println(tempDir.getAbsolutePath());
        // CHECKSTYLE:ON
    }
}
