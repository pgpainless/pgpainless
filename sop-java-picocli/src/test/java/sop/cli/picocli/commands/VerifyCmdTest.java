/*
 * Copyright 2020 Paul Schaub.
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

import com.ginsberg.junit.exit.ExpectSystemExitWithStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import sop.SOP;
import sop.Verification;
import sop.cli.picocli.DateParser;
import sop.cli.picocli.SopCLI;
import sop.exception.SOPGPException;
import sop.operation.Verify;
import sop.util.UTCUtil;

public class VerifyCmdTest {

    Verify verify;
    File signature;
    File cert;

    PrintStream originalSout;

    @BeforeEach
    public void prepare() throws SOPGPException.UnsupportedOption, SOPGPException.BadData, SOPGPException.NoSignature, IOException {
        originalSout = System.out;

        verify = mock(Verify.class);
        when(verify.notBefore(any())).thenReturn(verify);
        when(verify.notAfter(any())).thenReturn(verify);
        when(verify.cert(any())).thenReturn(verify);
        when(verify.signatures(any())).thenReturn(verify);
        when(verify.data(any())).thenReturn(
                Collections.singletonList(
                        new Verification(
                                UTCUtil.parseUTCDate("2019-10-29T18:36:45Z"),
                                "EB85BB5FA33A75E15E944E63F231550C4F47E38E",
                                "EB85BB5FA33A75E15E944E63F231550C4F47E38E")
                )
        );

        SOP sop = mock(SOP.class);
        when(sop.verify()).thenReturn(verify);

        SopCLI.setSopInstance(sop);

        signature = File.createTempFile("signature-", ".asc");
        cert = File.createTempFile("cert-", ".asc");
    }

    @AfterEach
    public void restoreSout() {
        System.setOut(originalSout);
    }

    @Test
    public void notAfter_passedDown() throws SOPGPException.UnsupportedOption {
        Date date = UTCUtil.parseUTCDate("2019-10-29T18:36:45Z");
        SopCLI.main(new String[] {"verify", "--not-after", "2019-10-29T18:36:45Z", signature.getAbsolutePath(), cert.getAbsolutePath()});
        verify(verify, times(1)).notAfter(date);
    }

    @Test
    public void notAfter_now() throws SOPGPException.UnsupportedOption {
        Date now = new Date();
        SopCLI.main(new String[] {"verify", "--not-after", "now", signature.getAbsolutePath(), cert.getAbsolutePath()});
        verify(verify, times(1)).notAfter(dateMatcher(now));
    }

    @Test
    public void notAfter_dashCountsAsEndOfTime() throws SOPGPException.UnsupportedOption {
        SopCLI.main(new String[] {"verify", "--not-after", "-", signature.getAbsolutePath(), cert.getAbsolutePath()});
        verify(verify, times(1)).notAfter(DateParser.END_OF_TIME);
    }

    @Test
    @ExpectSystemExitWithStatus(37)
    public void notAfter_unsupportedOptionCausesExit37() throws SOPGPException.UnsupportedOption {
        when(verify.notAfter(any())).thenThrow(new SOPGPException.UnsupportedOption("Setting upper signature date boundary not supported."));
        SopCLI.main(new String[] {"verify", "--not-after", "2019-10-29T18:36:45Z", signature.getAbsolutePath(), cert.getAbsolutePath()});
    }

    @Test
    public void notBefore_passedDown() throws SOPGPException.UnsupportedOption {
        Date date = UTCUtil.parseUTCDate("2019-10-29T18:36:45Z");
        SopCLI.main(new String[] {"verify", "--not-before", "2019-10-29T18:36:45Z", signature.getAbsolutePath(), cert.getAbsolutePath()});
        verify(verify, times(1)).notBefore(date);
    }

    @Test
    public void notBefore_now() throws SOPGPException.UnsupportedOption {
        Date now = new Date();
        SopCLI.main(new String[] {"verify", "--not-before", "now", signature.getAbsolutePath(), cert.getAbsolutePath()});
        verify(verify, times(1)).notBefore(dateMatcher(now));
    }

    @Test
    public void notBefore_dashCountsAsBeginningOfTime() throws SOPGPException.UnsupportedOption {
        SopCLI.main(new String[] {"verify", "--not-before", "-", signature.getAbsolutePath(), cert.getAbsolutePath()});
        verify(verify, times(1)).notBefore(DateParser.BEGINNING_OF_TIME);
    }

    @Test
    @ExpectSystemExitWithStatus(37)
    public void notBefore_unsupportedOptionCausesExit37() throws SOPGPException.UnsupportedOption {
        when(verify.notBefore(any())).thenThrow(new SOPGPException.UnsupportedOption("Setting lower signature date boundary not supported."));
        SopCLI.main(new String[] {"verify", "--not-before", "2019-10-29T18:36:45Z", signature.getAbsolutePath(), cert.getAbsolutePath()});
    }

    @Test
    public void notBeforeAndNotAfterAreCalledWithDefaultValues() throws SOPGPException.UnsupportedOption {
        SopCLI.main(new String[] {"verify", signature.getAbsolutePath(), cert.getAbsolutePath()});
        verify(verify, times(1)).notAfter(dateMatcher(new Date()));
        verify(verify, times(1)).notBefore(DateParser.BEGINNING_OF_TIME);
    }

    private static Date dateMatcher(Date date) {
        return ArgumentMatchers.argThat(argument -> Math.abs(argument.getTime() - date.getTime()) < 1000);
    }

    @Test
    @ExpectSystemExitWithStatus(1)
    public void cert_fileNotFoundCausesExit1() {
        SopCLI.main(new String[] {"verify", signature.getAbsolutePath(), "invalid.asc"});
    }

    @Test
    @ExpectSystemExitWithStatus(41)
    public void cert_badDataCausesExit41() throws SOPGPException.BadData {
        when(verify.cert(any())).thenThrow(new SOPGPException.BadData(new IOException()));
        SopCLI.main(new String[] {"verify", signature.getAbsolutePath(), cert.getAbsolutePath()});
    }

    @Test
    @ExpectSystemExitWithStatus(1)
    public void signature_fileNotFoundCausesExit1() {
        SopCLI.main(new String[] {"verify", "invalid.sig", cert.getAbsolutePath()});
    }

    @Test
    @ExpectSystemExitWithStatus(41)
    public void signature_badDataCausesExit41() throws SOPGPException.BadData {
        when(verify.signatures(any())).thenThrow(new SOPGPException.BadData(new IOException()));
        SopCLI.main(new String[] {"verify", signature.getAbsolutePath(), cert.getAbsolutePath()});
    }

    @Test
    @ExpectSystemExitWithStatus(3)
    public void data_noSignaturesCausesExit3() throws SOPGPException.NoSignature, IOException, SOPGPException.BadData {
        when(verify.data(any())).thenThrow(new SOPGPException.NoSignature());
        SopCLI.main(new String[] {"verify", signature.getAbsolutePath(), cert.getAbsolutePath()});
    }

    @Test
    @ExpectSystemExitWithStatus(41)
    public void data_badDataCausesExit41() throws SOPGPException.NoSignature, IOException, SOPGPException.BadData {
        when(verify.data(any())).thenThrow(new SOPGPException.BadData(new IOException()));
        SopCLI.main(new String[] {"verify", signature.getAbsolutePath(), cert.getAbsolutePath()});
    }

    @Test
    public void resultIsPrintedProperly() throws SOPGPException.NoSignature, IOException, SOPGPException.BadData {
        when(verify.data(any())).thenReturn(Arrays.asList(
                new Verification(UTCUtil.parseUTCDate("2019-10-29T18:36:45Z"),
                        "EB85BB5FA33A75E15E944E63F231550C4F47E38E",
                        "EB85BB5FA33A75E15E944E63F231550C4F47E38E"),
                new Verification(UTCUtil.parseUTCDate("2019-10-24T23:48:29Z"),
                        "C90E6D36200A1B922A1509E77618196529AE5FF8",
                        "C4BC2DDB38CCE96485EBE9C2F20691179038E5C6")
        ));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));

        SopCLI.main(new String[] {"verify", signature.getAbsolutePath(), cert.getAbsolutePath()});

        System.setOut(originalSout);

        String expected = "2019-10-29T18:36:45Z EB85BB5FA33A75E15E944E63F231550C4F47E38E EB85BB5FA33A75E15E944E63F231550C4F47E38E\n" +
                "2019-10-24T23:48:29Z C90E6D36200A1B922A1509E77618196529AE5FF8 C4BC2DDB38CCE96485EBE9C2F20691179038E5C6\n";

        assertEquals(expected, out.toString());
    }
}
