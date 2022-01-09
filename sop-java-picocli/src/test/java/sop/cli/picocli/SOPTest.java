// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.cli.picocli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.ginsberg.junit.exit.ExpectSystemExitWithStatus;
import org.junit.jupiter.api.Test;
import sop.SOP;
import sop.operation.Armor;
import sop.operation.Dearmor;
import sop.operation.Decrypt;
import sop.operation.DetachInbandSignatureAndMessage;
import sop.operation.Encrypt;
import sop.operation.ExtractCert;
import sop.operation.GenerateKey;
import sop.operation.Sign;
import sop.operation.Verify;
import sop.operation.Version;

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

    @Test
    public void UnsupportedSubcommandsTest() {
        SOP nullCommandSOP = new SOP() {
            @Override
            public Version version() {
                return null;
            }

            @Override
            public GenerateKey generateKey() {
                return null;
            }

            @Override
            public ExtractCert extractCert() {
                return null;
            }

            @Override
            public Sign sign() {
                return null;
            }

            @Override
            public Verify verify() {
                return null;
            }

            @Override
            public Encrypt encrypt() {
                return null;
            }

            @Override
            public Decrypt decrypt() {
                return null;
            }

            @Override
            public Armor armor() {
                return null;
            }

            @Override
            public Dearmor dearmor() {
                return null;
            }

            @Override
            public DetachInbandSignatureAndMessage detachInbandSignatureAndMessage() {
                return null;
            }
        };
        SopCLI.setSopInstance(nullCommandSOP);

        List<String[]> commands = new ArrayList<>();
        commands.add(new String[] {"armor"});
        commands.add(new String[] {"dearmor"});
        commands.add(new String[] {"decrypt"});
        commands.add(new String[] {"detach-inband-signature-and-message"});
        commands.add(new String[] {"encrypt"});
        commands.add(new String[] {"extract-cert"});
        commands.add(new String[] {"generate-key"});
        commands.add(new String[] {"sign"});
        commands.add(new String[] {"verify", "signature.asc", "cert.asc"});
        commands.add(new String[] {"version"});

        for (String[] command : commands) {
            int exit = SopCLI.execute(command);
            assertEquals(69, exit, "Unexpected exit code for non-implemented command " + Arrays.toString(command) + ": " + exit);
        }
    }
}
