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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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
import sop.operation.ExtractCert;

public class ExtractCertCmdTest {

    ExtractCert extractCert;

    @BeforeEach
    public void mockComponents() throws IOException, SOPGPException.BadData {
        extractCert = mock(ExtractCert.class);
        when(extractCert.key(any())).thenReturn(new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) {
            }
        });

        SOP sop = mock(SOP.class);
        when(sop.extractCert()).thenReturn(extractCert);

        SopCLI.setSopInstance(sop);
    }

    @Test
    public void noArmor_notCalledByDefault() {
        SopCLI.main(new String[] {"extract-cert"});
        verify(extractCert, never()).noArmor();
    }

    @Test
    public void noArmor_passedDown() {
        SopCLI.main(new String[] {"extract-cert", "--no-armor"});
        verify(extractCert, times(1)).noArmor();
    }

    @Test
    @ExpectSystemExitWithStatus(1)
    public void key_ioExceptionCausesExit1() throws IOException, SOPGPException.BadData {
        when(extractCert.key(any())).thenReturn(new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) throws IOException {
                throw new IOException();
            }
        });
        SopCLI.main(new String[] {"extract-cert"});
    }

    @Test
    @ExpectSystemExitWithStatus(41)
    public void key_badDataCausesExit41() throws IOException, SOPGPException.BadData {
        when(extractCert.key(any())).thenThrow(new SOPGPException.BadData(new IOException()));
        SopCLI.main(new String[] {"extract-cert"});
    }
}
