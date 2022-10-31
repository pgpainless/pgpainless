// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.util.Passphrase;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class HideArmorHeadersTest {

    @Test
    public void testVersionHeaderIsOmitted() throws PGPException, IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(ProducerOptions.encrypt(
                        EncryptionOptions.get()
                                .addPassphrase(Passphrase.fromPassword("sw0rdf1sh")))
                        .setHideArmorHeaders(true));

        encryptionStream.write("Hello, World!\n".getBytes());
        encryptionStream.close();

        assertTrue(out.toString().startsWith("-----BEGIN PGP MESSAGE-----\n\n")); // No "Version: PGPainless"
    }
}
