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
import org.mockito.InOrder;
import org.mockito.Mockito;
import sop.Ready;
import sop.SOP;
import sop.cli.picocli.SopCLI;
import sop.exception.SOPGPException;
import sop.operation.GenerateKey;

public class GenerateKeyCmdTest {

    GenerateKey generateKey;

    @BeforeEach
    public void mockComponents() throws SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.MissingArg, IOException {
        generateKey = mock(GenerateKey.class);
        when(generateKey.generate()).thenReturn(new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) {

            }
        });

        SOP sop = mock(SOP.class);
        when(sop.generateKey()).thenReturn(generateKey);

        SopCLI.setSopInstance(sop);
    }

    @Test
    public void noArmor_notCalledByDefault() {
        SopCLI.main(new String[] {"generate-key", "Alice"});
        verify(generateKey, never()).noArmor();
    }

    @Test
    public void noArmor_passedDown() {
        SopCLI.main(new String[] {"generate-key", "--no-armor", "Alice"});
        verify(generateKey, times(1)).noArmor();
    }

    @Test
    public void userId_multipleUserIdsPassedDownInProperOrder() {
        SopCLI.main(new String[] {"generate-key", "Alice <alice@pgpainless.org>", "Bob <bob@pgpainless.org>"});

        InOrder inOrder = Mockito.inOrder(generateKey);
        inOrder.verify(generateKey).userId("Alice <alice@pgpainless.org>");
        inOrder.verify(generateKey).userId("Bob <bob@pgpainless.org>");

        verify(generateKey, times(2)).userId(any());
    }

    @Test
    @ExpectSystemExitWithStatus(19)
    public void missingArgumentCausesExit19() throws SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.MissingArg, IOException {
        // TODO: RFC4880-bis and the current Stateless OpenPGP CLI spec allow keys to have no user-ids,
        //  so we might want to change this test in the future.
        when(generateKey.generate()).thenThrow(new SOPGPException.MissingArg("Missing user-id."));
        SopCLI.main(new String[] {"generate-key"});
    }

    @Test
    @ExpectSystemExitWithStatus(13)
    public void unsupportedAsymmetricAlgorithmCausesExit13() throws SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.MissingArg, IOException {
        when(generateKey.generate()).thenThrow(new SOPGPException.UnsupportedAsymmetricAlgo(new Exception()));
        SopCLI.main(new String[] {"generate-key", "Alice"});
    }

    @Test
    @ExpectSystemExitWithStatus(1)
    public void ioExceptionCausesExit1() throws SOPGPException.UnsupportedAsymmetricAlgo, SOPGPException.MissingArg, IOException {
        when(generateKey.generate()).thenReturn(new Ready() {
            @Override
            public void writeTo(OutputStream outputStream) throws IOException {
                throw new IOException();
            }
        });
        SopCLI.main(new String[] {"generate-key", "Alice"});
    }
}
