/*
 * Copyright 2018 Paul Schaub.
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
package org.pgpainless;

import static junit.framework.TestCase.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.junit.Test;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.util.Passphrase;

public class SymmetricTest {

    private static final Logger LOGGER = Logger.getLogger(SymmetricTest.class.getName());

    private static final String message = "I grew up with the understanding that the world " +
            "I lived in was one where people enjoyed a sort of freedom " +
            "to communicate with each other in privacy, without it " +
            "being monitored, without it being measured or analyzed " +
            "or sort of judged by these shadowy figures or systems, " +
            "any time they mention anything that travels across " +
            "public lines.\n" +
            "\n" +
            "- Edward Snowden -";

    @Test
    public void testSymmetricEncryptionDecryption() throws IOException, PGPException {
        byte[] plain = message.getBytes();
        Passphrase passphrase = new Passphrase("choose_a_better_password_please".toCharArray());
        byte[] enc = PGPainless.encryptWithPassword(plain, passphrase, SymmetricKeyAlgorithm.AES_128);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armor = new ArmoredOutputStream(out);
        armor.write(enc);
        armor.flush();
        armor.close();

        // Print cipher text for validation with GnuPG.
        LOGGER.log(Level.INFO, new String(out.toByteArray()));

        byte[] plain2 = PGPainless.decryptWithPassword(enc, passphrase);
        assertTrue(Arrays.equals(plain, plain2));
    }
}
