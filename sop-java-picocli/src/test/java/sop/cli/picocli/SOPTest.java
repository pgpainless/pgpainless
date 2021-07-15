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
package sop.cli.picocli;

import static org.mockito.Mockito.mock;

import com.ginsberg.junit.exit.ExpectSystemExitWithStatus;
import org.junit.jupiter.api.Test;
import sop.SOP;

public class SOPTest {

    @Test
    @ExpectSystemExitWithStatus(69)
    public void assertExitOnInvalidSubcommand() {
        SOP sop = mock(SOP.class);
        SopCLI.setSopInstance(sop);

        SopCLI.main(new String[] {"invalid"});
    }

    @Test
    @ExpectSystemExitWithStatus(1)
    public void assertThrowsIfNoSOPBackendSet() {
        SopCLI.SOP_INSTANCE = null;
        // At this point, no SOP backend is set, so an InvalidStateException triggers exit(1)
        SopCLI.main(new String[] {"armor"});
    }
}
