// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.cli.picocli.commands;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.OutputStream;

import com.ginsberg.junit.exit.ExpectSystemExitWithStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import sop.Ready;
import sop.SOP;
import sop.cli.picocli.SopCLI;
import sop.exception.SOPGPException;
import sop.operation.Dearmor;

public class DearmorCmdTest {

    private SOP sop;
    private Dearmor dearmor;

    @BeforeEach
    public void mockComponents() throws IOException, SOPGPException.BadData {
        sop = mock(SOP.class);
        dearmor = mock(Dearmor.class);
        when(dearmor.data(any())).thenReturn(nopReady());
        when(sop.dearmor()).thenReturn(dearmor);

        SopCLI.setSopInstance(sop);
    }

    private static Ready nopReady() {
        return new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) {
            }
        };
    }

    @Test
    public void assertDataIsCalled() throws IOException, SOPGPException.BadData {
        SopCLI.main(new String[] {"dearmor"});
        verify(dearmor, times(1)).data(any());
    }

    @Test
    @ExpectSystemExitWithStatus(41)
    public void assertBadDataCausesExit41() throws IOException, SOPGPException.BadData {
        when(dearmor.data(any())).thenThrow(new SOPGPException.BadData(new IOException("invalid armor")));
        SopCLI.main(new String[] {"dearmor"});
    }
}
