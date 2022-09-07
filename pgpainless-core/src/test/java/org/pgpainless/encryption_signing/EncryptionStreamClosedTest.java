// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.util.TestAllImplementations;
import org.pgpainless.s2k.Passphrase;

public class EncryptionStreamClosedTest {

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testStreamHasToBeClosedBeforeGetResultCanBeCalled() throws IOException, PGPException {
        OutputStream out = new ByteArrayOutputStream();
        EncryptionStream stream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(ProducerOptions.encrypt(EncryptionOptions.encryptCommunications()
                .addPassphrase(Passphrase.fromPassword("dummy"))));

        // No close() called => getResult throws
        assertThrows(IllegalStateException.class, stream::getResult);
    }
}
