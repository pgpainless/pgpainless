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
package org.pgpainless.key.generation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.junit.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.collection.PGPKeyRing;
import org.pgpainless.key.generation.type.RSA;
import org.pgpainless.key.generation.type.length.RsaLength;

public class GenerateKeyWithAdditionalUserIdTest {

    @Test
    public void test() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {
        PGPKeyRing keyRing = PGPainless.generateKeyRing()
                .withMasterKey(KeySpec.getBuilder(RSA.withLength(RsaLength._3072))
                        .withDefaultKeyFlags()
                        .withDefaultAlgorithms())
                .withPrimaryUserId("primary@user.id")
                .withAdditionalUserId("additional@user.id")
                .withAdditionalUserId("additional2@user.id")
                .withAdditionalUserId("\ttrimThis@user.id     ")
                .withoutPassphrase()
                .build();

        Iterator<String> userIds = keyRing.getPublicKeys().getPublicKey().getUserIDs();
        assertEquals("primary@user.id", userIds.next());
        assertEquals("additional@user.id", userIds.next());
        assertEquals("additional2@user.id", userIds.next());
        assertEquals("trimThis@user.id", userIds.next());
        assertFalse(userIds.hasNext());

        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ArmoredOutputStream armor = new ArmoredOutputStream(byteOut);
        keyRing.getSecretKeys().encode(armor);
        armor.close();

        // echo this | gpg --list-packets
        // CHECKSTYLE:OFF
        System.out.println(byteOut.toString("UTF-8"));
        // CHECKSTYLE:ON
    }
}
