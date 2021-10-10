// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.cli.picocli.commands;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import com.ginsberg.junit.exit.ExpectSystemExitWithStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import sop.Ready;
import sop.SOP;
import sop.cli.picocli.SopCLI;
import sop.exception.SOPGPException;
import sop.operation.Sign;

public class SignCmdTest {

    Sign sign;
    File keyFile;

    @BeforeEach
    public void mockComponents() throws IOException, SOPGPException.ExpectedText {
        sign = mock(Sign.class);
        when(sign.data((InputStream) any())).thenReturn(new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) {

            }
        });

        SOP sop = mock(SOP.class);
        when(sop.sign()).thenReturn(sign);

        SopCLI.setSopInstance(sop);

        keyFile = File.createTempFile("sign-", ".asc");
    }

    @Test
    public void as_optionsAreCaseInsensitive() {
        SopCLI.main(new String[] {"sign", "--as", "Binary", keyFile.getAbsolutePath()});
        SopCLI.main(new String[] {"sign", "--as", "binary", keyFile.getAbsolutePath()});
        SopCLI.main(new String[] {"sign", "--as", "BINARY", keyFile.getAbsolutePath()});
    }

    @Test
    @ExpectSystemExitWithStatus(37)
    public void as_invalidOptionCausesExit37() {
        SopCLI.main(new String[] {"sign", "--as", "Invalid", keyFile.getAbsolutePath()});
    }

    @Test
    @ExpectSystemExitWithStatus(37)
    public void as_unsupportedOptionCausesExit37() throws SOPGPException.UnsupportedOption {
        when(sign.mode(any())).thenThrow(new SOPGPException.UnsupportedOption("Setting signing mode not supported."));
        SopCLI.main(new String[] {"sign", "--as", "binary", keyFile.getAbsolutePath()});
    }

    @Test
    @ExpectSystemExitWithStatus(1)
    public void key_nonExistentKeyFileCausesExit1() {
        SopCLI.main(new String[] {"sign", "invalid.asc"});
    }

    @Test
    @ExpectSystemExitWithStatus(1)
    public void key_keyIsProtectedCausesExit1() throws SOPGPException.KeyIsProtected, IOException, SOPGPException.BadData {
        when(sign.key((InputStream) any())).thenThrow(new SOPGPException.KeyIsProtected());
        SopCLI.main(new String[] {"sign", keyFile.getAbsolutePath()});
    }

    @Test
    @ExpectSystemExitWithStatus(41)
    public void key_badDataCausesExit41() throws SOPGPException.KeyIsProtected, IOException, SOPGPException.BadData {
        when(sign.key((InputStream) any())).thenThrow(new SOPGPException.BadData(new IOException()));
        SopCLI.main(new String[] {"sign", keyFile.getAbsolutePath()});
    }

    @Test
    @ExpectSystemExitWithStatus(19)
    public void key_missingKeyFileCausesExit19() {
        SopCLI.main(new String[] {"sign"});
    }

    @Test
    public void noArmor_notCalledByDefault() {
        SopCLI.main(new String[] {"sign", keyFile.getAbsolutePath()});
        verify(sign, never()).noArmor();
    }

    @Test
    public void noArmor_passedDown() {
        SopCLI.main(new String[] {"sign", "--no-armor", keyFile.getAbsolutePath()});
        verify(sign, times(1)).noArmor();
    }

    @Test
    @ExpectSystemExitWithStatus(1)
    public void data_ioExceptionCausesExit1() throws IOException, SOPGPException.ExpectedText {
        when(sign.data((InputStream) any())).thenReturn(new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) throws IOException {
                throw new IOException();
            }
        });
        SopCLI.main(new String[] {"sign", keyFile.getAbsolutePath()});
    }

    @Test
    @ExpectSystemExitWithStatus(53)
    public void data_expectedTextExceptionCausesExit53() throws IOException, SOPGPException.ExpectedText {
        when(sign.data((InputStream) any())).thenThrow(new SOPGPException.ExpectedText());
        SopCLI.main(new String[] {"sign", keyFile.getAbsolutePath()});
    }
}
