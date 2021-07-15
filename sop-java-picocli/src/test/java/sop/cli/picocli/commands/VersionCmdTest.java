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

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ginsberg.junit.exit.ExpectSystemExitWithStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import sop.SOP;
import sop.cli.picocli.SopCLI;
import sop.operation.Version;

public class VersionCmdTest {

    private SOP sop;
    private Version version;

    @BeforeEach
    public void mockComponents() {
        sop = mock(SOP.class);
        version = mock(Version.class);
        when(version.getName()).thenReturn("MockSop");
        when(version.getVersion()).thenReturn("1.0");
        when(sop.version()).thenReturn(version);

        SopCLI.setSopInstance(sop);
    }

    @Test
    public void assertVersionCommandWorks() {
        SopCLI.main(new String[] {"version"});
        verify(version, times(1)).getVersion();
        verify(version, times(1)).getName();
    }

    @Test
    @ExpectSystemExitWithStatus(37)
    public void assertInvalidOptionResultsInExit37() {
        SopCLI.main(new String[] {"version", "--invalid"});
    }
}
