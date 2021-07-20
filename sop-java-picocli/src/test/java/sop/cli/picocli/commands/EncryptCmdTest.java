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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;

import com.ginsberg.junit.exit.ExpectSystemExitWithStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import sop.Ready;
import sop.SOP;
import sop.cli.picocli.SopCLI;
import sop.enums.EncryptAs;
import sop.exception.SOPGPException;
import sop.operation.Encrypt;

public class EncryptCmdTest {

    Encrypt encrypt;

    @BeforeEach
    public void mockComponents() throws IOException {
        encrypt = mock(Encrypt.class);
        when(encrypt.plaintext(any())).thenReturn(new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) {

            }
        });

        SOP sop = mock(SOP.class);
        when(sop.encrypt()).thenReturn(encrypt);

        SopCLI.setSopInstance(sop);
    }

    @Test
    @ExpectSystemExitWithStatus(19)
    public void missingBothPasswordAndCertFileCauseExit19() {
        SopCLI.main(new String[] {"encrypt", "--no-armor"});
    }

    @Test
    @ExpectSystemExitWithStatus(37)
    public void as_unsupportedEncryptAsCausesExit37() throws SOPGPException.UnsupportedOption {
        when(encrypt.mode(any())).thenThrow(new SOPGPException.UnsupportedOption("Setting encryption mode not supported."));

        SopCLI.main(new String[] {"encrypt", "--as", "Binary"});
    }

    @Test
    @ExpectSystemExitWithStatus(37)
    public void as_invalidModeOptionCausesExit37() {
        SopCLI.main(new String[] {"encrypt", "--as", "invalid"});
    }

    @Test
    public void as_modeIsPassedDown() throws SOPGPException.UnsupportedOption {
        for (EncryptAs mode : EncryptAs.values()) {
            SopCLI.main(new String[] {"encrypt", "--as", mode.name(), "--with-password", "0rbit"});
            verify(encrypt, times(1)).mode(mode);
        }
    }

    @Test
    @ExpectSystemExitWithStatus(31)
    public void withPassword_notHumanReadablePasswordCausesExit31() throws SOPGPException.PasswordNotHumanReadable, SOPGPException.UnsupportedOption {
        when(encrypt.withPassword("pretendThisIsNotReadable")).thenThrow(new SOPGPException.PasswordNotHumanReadable());

        SopCLI.main(new String[] {"encrypt", "--with-password", "pretendThisIsNotReadable"});
    }

    @Test
    @ExpectSystemExitWithStatus(37)
    public void withPassword_unsupportedWithPasswordCausesExit37() throws SOPGPException.PasswordNotHumanReadable, SOPGPException.UnsupportedOption {
        when(encrypt.withPassword(any())).thenThrow(new SOPGPException.UnsupportedOption("Encrypting with password not supported."));

        SopCLI.main(new String[] {"encrypt", "--with-password", "orange"});
    }

    @Test
    public void signWith_multipleTimesGetPassedDown() throws IOException, SOPGPException.KeyIsProtected, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.CertCannotSign, SOPGPException.BadData {
        File keyFile1 = File.createTempFile("sign-with-1-", ".asc");
        File keyFile2 = File.createTempFile("sign-with-2-", ".asc");

        SopCLI.main(new String[] {"encrypt", "--with-password", "password", "--sign-with", keyFile1.getAbsolutePath(), "--sign-with", keyFile2.getAbsolutePath()});
        verify(encrypt, times(2)).signWith(any());
    }

    @Test
    @ExpectSystemExitWithStatus(61)
    public void signWith_nonExistentKeyFileCausesExit61() {
        SopCLI.main(new String[] {"encrypt", "--with-password", "admin", "--sign-with", "nonExistent.asc"});
    }

    @Test
    @ExpectSystemExitWithStatus(67)
    public void signWith_keyIsProtectedCausesExit67() throws SOPGPException.KeyIsProtected, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.CertCannotSign, SOPGPException.BadData, IOException {
        when(encrypt.signWith(any())).thenThrow(new SOPGPException.KeyIsProtected());
        File keyFile = File.createTempFile("sign-with", ".asc");
        SopCLI.main(new String[] {"encrypt", "--sign-with", keyFile.getAbsolutePath(), "--with-password", "starship"});
    }

    @Test
    @ExpectSystemExitWithStatus(13)
    public void signWith_unsupportedAsymmetricAlgoCausesExit13() throws SOPGPException.KeyIsProtected, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.CertCannotSign, SOPGPException.BadData, IOException {
        when(encrypt.signWith(any())).thenThrow(new SOPGPException.UnsupportedAsymmetricAlgo("Unsupported asymmetric algorithm.", new Exception()));
        File keyFile = File.createTempFile("sign-with", ".asc");
        SopCLI.main(new String[] {"encrypt", "--with-password", "123456", "--sign-with", keyFile.getAbsolutePath()});
    }

    @Test
    @ExpectSystemExitWithStatus(1)
    public void signWith_certCannotSignCausesExit1() throws IOException, SOPGPException.KeyIsProtected, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.CertCannotSign, SOPGPException.BadData {
        when(encrypt.signWith(any())).thenThrow(new SOPGPException.CertCannotSign());
        File keyFile = File.createTempFile("sign-with", ".asc");
        SopCLI.main(new String[] {"encrypt", "--with-password", "dragon", "--sign-with", keyFile.getAbsolutePath()});
    }

    @Test
    @ExpectSystemExitWithStatus(41)
    public void signWith_badDataCausesExit41() throws SOPGPException.KeyIsProtected, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.CertCannotSign, SOPGPException.BadData, IOException {
        when(encrypt.signWith(any())).thenThrow(new SOPGPException.BadData(new IOException()));
        File keyFile = File.createTempFile("sign-with", ".asc");
        SopCLI.main(new String[] {"encrypt", "--with-password", "orange", "--sign-with", keyFile.getAbsolutePath()});
    }

    @Test
    @ExpectSystemExitWithStatus(61)
    public void cert_nonExistentCertFileCausesExit61() {
        SopCLI.main(new String[] {"encrypt", "invalid.asc"});
    }

    @Test
    @ExpectSystemExitWithStatus(13)
    public void cert_unsupportedAsymmetricAlgorithmCausesExit13() throws IOException, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.CertCannotEncrypt, SOPGPException.BadData {
        when(encrypt.withCert(any())).thenThrow(new SOPGPException.UnsupportedAsymmetricAlgo("Unsupported asymmetric algorithm.", new Exception()));
        File certFile = File.createTempFile("cert", ".asc");
        SopCLI.main(new String[] {"encrypt", certFile.getAbsolutePath()});
    }

    @Test
    @ExpectSystemExitWithStatus(17)
    public void cert_certCannotEncryptCausesExit17() throws IOException, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.CertCannotEncrypt, SOPGPException.BadData {
        when(encrypt.withCert(any())).thenThrow(new SOPGPException.CertCannotEncrypt("Certificate cannot encrypt.", new Exception()));
        File certFile = File.createTempFile("cert", ".asc");
        SopCLI.main(new String[] {"encrypt", certFile.getAbsolutePath()});
    }

    @Test
    @ExpectSystemExitWithStatus(41)
    public void cert_badDataCausesExit41() throws IOException, SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.CertCannotEncrypt, SOPGPException.BadData {
        when(encrypt.withCert(any())).thenThrow(new SOPGPException.BadData(new IOException()));
        File certFile = File.createTempFile("cert", ".asc");
        SopCLI.main(new String[] {"encrypt", certFile.getAbsolutePath()});
    }

    @Test
    public void noArmor_notCalledByDefault() {
        SopCLI.main(new String[] {"encrypt", "--with-password", "clownfish"});
        verify(encrypt, never()).noArmor();
    }

    @Test
    public void noArmor_callGetsPassedDown() {
        SopCLI.main(new String[] {"encrypt", "--with-password", "monkey", "--no-armor"});
        verify(encrypt, times(1)).noArmor();
    }

    @Test
    @ExpectSystemExitWithStatus(1)
    public void writeTo_ioExceptionCausesExit1() throws IOException {
        when(encrypt.plaintext(any())).thenReturn(new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) throws IOException {
                throw new IOException();
            }
        });

        SopCLI.main(new String[] {"encrypt", "--with-password", "wildcat"});
    }
}
