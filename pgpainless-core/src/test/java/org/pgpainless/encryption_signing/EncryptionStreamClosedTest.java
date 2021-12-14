// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.pgpainless.PGPainless;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.util.Passphrase;
import org.pgpainless.util.TestImplementationFactoryProvider;

public class EncryptionStreamClosedTest {

    @ParameterizedTest
    @ArgumentsSource(TestImplementationFactoryProvider.class)
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
