// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

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
