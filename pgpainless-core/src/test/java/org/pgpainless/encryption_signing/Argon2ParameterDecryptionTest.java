// SPDX-FileCopyrightText: 2026 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.encryption_signing;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.MessageEncryptionMechanism;
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.exception.MissingDecryptionMethodException;
import org.pgpainless.util.Passphrase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class Argon2ParameterDecryptionTest {

    @Test
    public void testDecryptionArgon2Parameter() throws PGPException, IOException {
        PGPainless api = new PGPainless();
        SecureRandom rand = new SecureRandom();
        System.setProperty("org.bouncycastle.argon2.max_memory_exp", "30");
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPKeyEncryptionMethodGenerator argon2 = new BcPBEKeyEncryptionMethodGenerator(
                "sw0rdf1sh".toCharArray(), new S2K.Argon2Params(1, 4, 18, rand))
                .setSecureRandom(rand);
        EncryptionStream eOut = api.generateMessage()
                .onOutputStream(bOut)
                .withOptions(ProducerOptions.encrypt(
                        EncryptionOptions.get(api)
                                .overrideEncryptionMechanism(
                                        MessageEncryptionMechanism.aead(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB))
                                .addEncryptionMethod(argon2)
                ));
        eOut.write("Hello World".getBytes());
        eOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        System.setProperty("org.bouncycastle.argon2.max_memory_exp", "16");
        assertThrows(MissingDecryptionMethodException.class, () -> api.processMessage()
                .onInputStream(bIn)
                .withOptions(ConsumerOptions.get(api)
                        .addMessagePassphrase(Passphrase.fromPassword("sw0rdf1sh"))));
    }
}
