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
package org.pgpainless.encryption_signing;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.util.Passphrase;

public class EncryptionStreamClosedTest {

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void testStreamHasToBeClosedBeforeGetResultCanBeCalled(ImplementationFactory implementationFactory) throws IOException, PGPException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);
        OutputStream out = new ByteArrayOutputStream();
        EncryptionStream stream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(ProducerOptions.encrypt(EncryptionOptions.encryptCommunications()
                .addPassphrase(Passphrase.fromPassword("dummy"))));

        // No close() called => getResult throws
        assertThrows(IllegalStateException.class, stream::getResult);
    }
}
