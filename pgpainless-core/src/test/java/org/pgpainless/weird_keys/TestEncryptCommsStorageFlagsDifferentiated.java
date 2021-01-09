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
package org.pgpainless.weird_keys;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.encryption_signing.EncryptionBuilderInterface;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.util.KeyRingUtils;

public class TestEncryptCommsStorageFlagsDifferentiated {

    @Test
    public void testThatEncryptionDifferentiatesBetweenPurposeKeyFlags() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .withMasterKey(KeySpec.getBuilder(KeyType.RSA(RsaLength._3072))
                        .withKeyFlags(KeyFlag.CERTIFY_OTHER,
                                KeyFlag.SIGN_DATA,
                                KeyFlag.ENCRYPT_STORAGE // no ENCRYPT_COMMS
                        )
                        .withDefaultAlgorithms())
                .withPrimaryUserId("cannot@encrypt.comms")
                .withoutPassphrase()
                .build();
        PGPPublicKeyRing publicKeys = KeyRingUtils.publicKeyRingFrom(secretKeys);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionBuilderInterface.ToRecipients builder = PGPainless.encryptAndOrSign(EncryptionStream.Purpose.COMMUNICATIONS)
                .onOutputStream(out);

        // since the key does not carry the flag ENCRYPT_COMMS, it cannot be used by the stream.
        assertThrows(IllegalArgumentException.class, () -> builder.toRecipients(publicKeys));
    }
}
