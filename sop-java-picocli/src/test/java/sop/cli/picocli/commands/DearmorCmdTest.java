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
