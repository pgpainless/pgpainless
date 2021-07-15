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
package sop.cli.picocli.commands;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Date;

import com.ginsberg.junit.exit.ExpectSystemExitWithStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.ArgumentMatchers;
import sop.DecryptionResult;
import sop.ReadyWithResult;
import sop.SOP;
import sop.SessionKey;
import sop.Verification;
import sop.cli.picocli.DateParser;
import sop.cli.picocli.SopCLI;
import sop.exception.SOPGPException;
import sop.operation.Decrypt;
import sop.util.HexUtil;
import sop.util.UTCUtil;

public class DecryptCmdTest {

    private Decrypt decrypt;

    @BeforeEach
    public void mockComponents() throws SOPGPException.UnsupportedOption, SOPGPException.MissingArg, SOPGPException.BadData, SOPGPException.KeyIsProtected, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.PasswordNotHumanReadable, SOPGPException.CannotDecrypt {
        SOP sop = mock(SOP.class);
        decrypt = mock(Decrypt.class);

        when(decrypt.verifyNotAfter(any())).thenReturn(decrypt);
        when(decrypt.verifyNotBefore(any())).thenReturn(decrypt);
        when(decrypt.withPassword(any())).thenReturn(decrypt);
        when(decrypt.withSessionKey(any())).thenReturn(decrypt);
        when(decrypt.withKey(any())).thenReturn(decrypt);
        when(decrypt.ciphertext(any())).thenReturn(nopReadyWithResult());

        when(sop.decrypt()).thenReturn(decrypt);

        SopCLI.setSopInstance(sop);
    }

    private static ReadyWithResult<DecryptionResult> nopReadyWithResult() {
        return new ReadyWithResult<DecryptionResult>() {
            @Override
            public DecryptionResult writeTo(OutputStream outputStream) {
                return new DecryptionResult(null, Collections.emptyList());
            }
        };
    }

    @Test
    @ExpectSystemExitWithStatus(19)
    public void missingArgumentsExceptionCausesExit19() throws SOPGPException.MissingArg, SOPGPException.BadData, SOPGPException.CannotDecrypt {
        when(decrypt.ciphertext(any())).thenThrow(new SOPGPException.MissingArg("Missing arguments."));
        SopCLI.main(new String[] {"decrypt"});
    }

    @Test
    @ExpectSystemExitWithStatus(41)
    public void badDataExceptionCausesExit41() throws SOPGPException.MissingArg, SOPGPException.BadData, SOPGPException.CannotDecrypt {
        when(decrypt.ciphertext(any())).thenThrow(new SOPGPException.BadData(new IOException()));
        SopCLI.main(new String[] {"decrypt"});
    }

    @Test
    @ExpectSystemExitWithStatus(31)
    public void assertNotHumanReadablePasswordCausesExit31() throws SOPGPException.PasswordNotHumanReadable,
            SOPGPException.UnsupportedOption {
        when(decrypt.withPassword(any())).thenThrow(new SOPGPException.PasswordNotHumanReadable());
        SopCLI.main(new String[] {"decrypt", "--with-password", "pretendThisIsNotReadable"});
    }

    @Test
    public void assertWithPasswordPassesPasswordDown() throws SOPGPException.PasswordNotHumanReadable, SOPGPException.UnsupportedOption {
        SopCLI.main(new String[] {"decrypt", "--with-password", "orange"});
        verify(decrypt, times(1)).withPassword("orange");
    }

    @Test
    @ExpectSystemExitWithStatus(37)
    public void assertUnsupportedWithPasswordCausesExit37() throws SOPGPException.PasswordNotHumanReadable, SOPGPException.UnsupportedOption {
        when(decrypt.withPassword(any())).thenThrow(new SOPGPException.UnsupportedOption());
        SopCLI.main(new String[] {"decrypt", "--with-password", "swordfish"});
    }

    @Test
    public void assertDefaultTimeRangesAreUsedIfNotOverwritten() throws SOPGPException.UnsupportedOption {
        Date now = new Date();
        SopCLI.main(new String[] {"decrypt"});
        verify(decrypt, times(1)).verifyNotBefore(DateParser.BEGINNING_OF_TIME);
        verify(decrypt, times(1)).verifyNotAfter(
                ArgumentMatchers.argThat(argument -> {
                    // allow 1 second difference
                    return Math.abs(now.getTime() - argument.getTime()) <= 1000;
                }));
    }

    @Test
    public void assertVerifyNotAfterAndBeforeDashResultsInMaxTimeRange() throws SOPGPException.UnsupportedOption {
        SopCLI.main(new String[] {"decrypt", "--not-before", "-", "--not-after", "-"});
        verify(decrypt, times(1)).verifyNotBefore(DateParser.BEGINNING_OF_TIME);
        verify(decrypt, times(1)).verifyNotAfter(DateParser.END_OF_TIME);
    }

    @Test
    public void assertVerifyNotAfterAndBeforeNowResultsInMinTimeRange() throws SOPGPException.UnsupportedOption {
        Date now = new Date();
        ArgumentMatcher<Date> isMaxOneSecOff = argument -> {
            // Allow less than 1 second difference
            return Math.abs(now.getTime() - argument.getTime()) <= 1000;
        };

        SopCLI.main(new String[] {"decrypt", "--not-before", "now", "--not-after", "now"});
        verify(decrypt, times(1)).verifyNotAfter(ArgumentMatchers.argThat(isMaxOneSecOff));
        verify(decrypt, times(1)).verifyNotBefore(ArgumentMatchers.argThat(isMaxOneSecOff));
    }

    @Test
    @ExpectSystemExitWithStatus(1)
    public void assertMalformedDateInNotBeforeCausesExit1() {
        // ParserException causes exit(1)
        SopCLI.main(new String[] {"decrypt", "--not-before", "invalid"});
    }

    @Test
    @ExpectSystemExitWithStatus(1)
    public void assertMalformedDateInNotAfterCausesExit1() {
        // ParserException causes exit(1)
        SopCLI.main(new String[] {"decrypt", "--not-after", "invalid"});
    }

    @Test
    @ExpectSystemExitWithStatus(37)
    public void assertUnsupportedNotAfterCausesExit37() throws SOPGPException.UnsupportedOption {
        when(decrypt.verifyNotAfter(any())).thenThrow(new SOPGPException.UnsupportedOption());
        SopCLI.main(new String[] {"decrypt", "--not-after", "now"});
    }

    @Test
    @ExpectSystemExitWithStatus(37)
    public void assertUnsupportedNotBeforeCausesExit37() throws SOPGPException.UnsupportedOption {
        when(decrypt.verifyNotBefore(any())).thenThrow(new SOPGPException.UnsupportedOption());
        SopCLI.main(new String[] {"decrypt", "--not-before", "now"});
    }

    @Test
    @ExpectSystemExitWithStatus(1)
    public void assertExistingSessionKeyOutFileCausesExit1() throws IOException {
        File tempFile = File.createTempFile("existing-session-key-", ".tmp");
        tempFile.deleteOnExit();
        SopCLI.main(new String[] {"decrypt", "--session-key-out", tempFile.getAbsolutePath()});
    }

    @Test
    @ExpectSystemExitWithStatus(37)
    public void assertWhenSessionKeyCannotBeExtractedExit37() throws IOException {
        Path tempDir = Files.createTempDirectory("session-key-out-dir");
        File tempFile = new File(tempDir.toFile(), "session-key");
        tempFile.deleteOnExit();
        SopCLI.main(new String[] {"decrypt", "--session-key-out", tempFile.getAbsolutePath()});
    }

    @Test
    public void assertSessionKeyIsProperlyWrittenToSessionKeyFile() throws SOPGPException.CannotDecrypt, SOPGPException.MissingArg, SOPGPException.BadData, IOException {
        byte[] key = "C7CBDAF42537776F12509B5168793C26B93294E5ABDFA73224FB0177123E9137".getBytes(StandardCharsets.UTF_8);
        when(decrypt.ciphertext(any())).thenReturn(new ReadyWithResult<DecryptionResult>() {
            @Override
            public DecryptionResult writeTo(OutputStream outputStream) {
                return new DecryptionResult(
                        new SessionKey((byte) 9, key),
                        Collections.emptyList()
                );
            }
        });
        Path tempDir = Files.createTempDirectory("session-key-out-dir");
        File tempFile = new File(tempDir.toFile(), "session-key");
        tempFile.deleteOnExit();
        SopCLI.main(new String[] {"decrypt", "--session-key-out", tempFile.getAbsolutePath()});

        ByteArrayOutputStream bytesInFile = new ByteArrayOutputStream();
        try (FileInputStream fileIn = new FileInputStream(tempFile)) {
            byte[] buf = new byte[32];
            int read = fileIn.read(buf);
            while (read != -1) {
                bytesInFile.write(buf, 0, read);
                read = fileIn.read(buf);
            }
        }

        byte[] algAndKey = new byte[key.length + 1];
        algAndKey[0] = (byte) 9;
        System.arraycopy(key, 0, algAndKey, 1, key.length);
        assertArrayEquals(algAndKey, bytesInFile.toByteArray());
    }

    @Test
    @ExpectSystemExitWithStatus(29)
    public void assertUnableToDecryptExceptionResultsInExit29() throws SOPGPException.CannotDecrypt, SOPGPException.MissingArg, SOPGPException.BadData {
        when(decrypt.ciphertext(any())).thenThrow(new SOPGPException.CannotDecrypt());
        SopCLI.main(new String[] {"decrypt"});
    }

    @Test
    @ExpectSystemExitWithStatus(3)
    public void assertNoSignatureExceptionCausesExit3() throws SOPGPException.CannotDecrypt, SOPGPException.MissingArg, SOPGPException.BadData {
        when(decrypt.ciphertext(any())).thenReturn(new ReadyWithResult<DecryptionResult>() {
            @Override
            public DecryptionResult writeTo(OutputStream outputStream) throws SOPGPException.NoSignature {
                throw new SOPGPException.NoSignature();
            }
        });
        SopCLI.main(new String[] {"decrypt"});
    }

    @Test
    @ExpectSystemExitWithStatus(41)
    public void badDataInVerifyWithCausesExit41() throws IOException, SOPGPException.BadData {
        when(decrypt.verifyWithCert(any())).thenThrow(new SOPGPException.BadData(new IOException()));
        File tempFile = File.createTempFile("verify-with-", ".tmp");
        SopCLI.main(new String[] {"decrypt", "--verify-with", tempFile.getAbsolutePath()});
    }

    @Test
    @ExpectSystemExitWithStatus(1)
    public void unexistentCertFileCausesExit1() {
        SopCLI.main(new String[] {"decrypt", "--verify-with", "invalid"});
    }

    @Test
    public void existingVerifyOutFileIsUnlinkedBeforeVerification() throws IOException, SOPGPException.CannotDecrypt, SOPGPException.MissingArg, SOPGPException.BadData {
        File certFile = File.createTempFile("existing-verify-out-cert", ".asc");
        File existingVerifyOut = File.createTempFile("existing-verify-out", ".tmp");
        byte[] data = "some data".getBytes(StandardCharsets.UTF_8);
        try (FileOutputStream out = new FileOutputStream(existingVerifyOut)) {
            out.write(data);
        }
        Date date = UTCUtil.parseUTCDate("2021-07-11T20:58:23Z");
        when(decrypt.ciphertext(any())).thenReturn(new ReadyWithResult<DecryptionResult>() {
            @Override
            public DecryptionResult writeTo(OutputStream outputStream) {
                return new DecryptionResult(null, Collections.singletonList(
                        new Verification(
                                date,
                                "1B66A707819A920925BC6777C3E0AFC0B2DFF862",
                                "C8CD564EBF8D7BBA90611D8D071773658BF6BF86"))
                );
            }
        });

        SopCLI.main(new String[] {"decrypt", "--verify-out", existingVerifyOut.getAbsolutePath(), "--verify-with", certFile.getAbsolutePath()});
        try (BufferedReader reader = new BufferedReader(new FileReader(existingVerifyOut))) {
            String line = reader.readLine();
            assertEquals("2021-07-11T20:58:23Z 1B66A707819A920925BC6777C3E0AFC0B2DFF862 C8CD564EBF8D7BBA90611D8D071773658BF6BF86", line);
        }
    }

    @Test
    public void assertWithSessionKeyIsPassedDown() throws SOPGPException.UnsupportedOption {
        SessionKey key1 = new SessionKey((byte) 9, HexUtil.hexToBytes("C7CBDAF42537776F12509B5168793C26B93294E5ABDFA73224FB0177123E9137"));
        SessionKey key2 = new SessionKey((byte) 9, HexUtil.hexToBytes("FCA4BEAF687F48059CACC14FB019125CD57392BAB7037C707835925CBF9F7BCD"));
        SopCLI.main(new String[] {"decrypt",
                "--with-session-key", "9:C7CBDAF42537776F12509B5168793C26B93294E5ABDFA73224FB0177123E9137",
                "--with-session-key", "9:FCA4BEAF687F48059CACC14FB019125CD57392BAB7037C707835925CBF9F7BCD"});
        verify(decrypt).withSessionKey(key1);
        verify(decrypt).withSessionKey(key2);
    }

    @Test
    @ExpectSystemExitWithStatus(1)
    public void assertMalformedSessionKeysResultInExit1() {
        SopCLI.main(new String[] {"decrypt",
                "--with-session-key", "C7CBDAF42537776F12509B5168793C26B93294E5ABDFA73224FB0177123E9137"});
    }

    @Test
    @ExpectSystemExitWithStatus(41)
    public void assertBadDataInKeysResultsInExit41() throws SOPGPException.KeyIsProtected, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.BadData, IOException {
        when(decrypt.withKey(any())).thenThrow(new SOPGPException.BadData(new IOException()));
        File tempKeyFile = File.createTempFile("key-", ".tmp");
        SopCLI.main(new String[] {"decrypt", tempKeyFile.getAbsolutePath()});
    }

    @Test
    @ExpectSystemExitWithStatus(1)
    public void assertKeyFileNotFoundCausesExit1() {
        SopCLI.main(new String[] {"decrypt", "nonexistent-key"});
    }

    @Test
    @ExpectSystemExitWithStatus(1)
    public void assertProtectedKeyCausesExit1() throws IOException, SOPGPException.KeyIsProtected, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.BadData {
        when(decrypt.withKey(any())).thenThrow(new SOPGPException.KeyIsProtected());
        File tempKeyFile = File.createTempFile("key-", ".tmp");
        SopCLI.main(new String[] {"decrypt", tempKeyFile.getAbsolutePath()});
    }

    @Test
    @ExpectSystemExitWithStatus(13)
    public void assertUnsupportedAlgorithmExceptionCausesExit13() throws SOPGPException.KeyIsProtected, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.BadData, IOException {
        when(decrypt.withKey(any())).thenThrow(new SOPGPException.UnsupportedAsymmetricAlgo(new IOException()));
        File tempKeyFile = File.createTempFile("key-", ".tmp");
        SopCLI.main(new String[] {"decrypt", tempKeyFile.getAbsolutePath()});
    }

    @Test
    @ExpectSystemExitWithStatus(23)
    public void verifyOutWithoutVerifyWithCausesExit23() {
        SopCLI.main(new String[] {"decrypt", "--verify-out", "out.file"});
    }
}
