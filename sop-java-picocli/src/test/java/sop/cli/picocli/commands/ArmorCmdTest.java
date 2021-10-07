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

import java.io.IOException;
import java.io.OutputStream;

import com.ginsberg.junit.exit.ExpectSystemExitWithStatus;
import com.ginsberg.junit.exit.FailOnSystemExit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import sop.Ready;
import sop.SOP;
import sop.cli.picocli.SopCLI;
import sop.enums.ArmorLabel;
import sop.exception.SOPGPException;
import sop.operation.Armor;

public class ArmorCmdTest {

    private Armor armor;
    private SOP sop;

    @BeforeEach
    public void mockComponents() throws SOPGPException.BadData {
        armor = mock(Armor.class);
        sop = mock(SOP.class);
        when(sop.armor()).thenReturn(armor);
        when(armor.data(any())).thenReturn(nopReady());

        SopCLI.setSopInstance(sop);
    }

    @Test
    public void assertLabelIsNotCalledByDefault() throws SOPGPException.UnsupportedOption {
        SopCLI.main(new String[] {"armor"});
        verify(armor, never()).label(any());
    }

    @Test
    public void assertLabelIsCalledWhenFlaggedWithArgument() throws SOPGPException.UnsupportedOption {
        for (ArmorLabel label : ArmorLabel.values()) {
            SopCLI.main(new String[] {"armor", "--label", label.name()});
            verify(armor, times(1)).label(label);
        }
    }

    @Test
    public void assertDataIsAlwaysCalled() throws SOPGPException.BadData {
        SopCLI.main(new String[] {"armor"});
        verify(armor, times(1)).data(any());
    }

    @Test
    @ExpectSystemExitWithStatus(37)
    public void assertThrowsForInvalidLabel() {
        SopCLI.main(new String[] {"armor", "--label", "Invalid"});
    }

    @Test
    @ExpectSystemExitWithStatus(37)
    public void ifLabelsUnsupportedExit37() throws SOPGPException.UnsupportedOption {
        when(armor.label(any())).thenThrow(new SOPGPException.UnsupportedOption("Custom Armor labels are not supported."));

        SopCLI.main(new String[] {"armor", "--label", "Sig"});
    }

    @Test
    @ExpectSystemExitWithStatus(41)
    public void ifBadDataExit41() throws SOPGPException.BadData {
        when(armor.data(any())).thenThrow(new SOPGPException.BadData(new IOException()));

        SopCLI.main(new String[] {"armor"});
    }

    @Test
    @FailOnSystemExit
    public void ifNoErrorsNoExit() {
        when(sop.armor()).thenReturn(armor);

        SopCLI.main(new String[] {"armor"});
    }

    private static Ready nopReady() {
        return new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) {
            }
        };
    }
}
