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
package org.pgpainless.key.info;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.xdh.XDHCurve;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.key.util.KeyRingUtils;
import org.pgpainless.key.util.SignatureUtils;

public class UserIdRevocationTest {

    @Test
    public void test() throws IOException, PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InterruptedException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .withSubKey(KeySpec.getBuilder(KeyType.XDH(XDHCurve._X25519))
                        .withKeyFlags(KeyFlag.ENCRYPT_COMMS)
                        .withDefaultAlgorithms())
                .withMasterKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519))
                        .withKeyFlags(KeyFlag.SIGN_DATA, KeyFlag.CERTIFY_OTHER)
                        .withDefaultAlgorithms())
                .withPrimaryUserId("primary@key.id")
                .withAdditionalUserId("secondary@key.id")
                .withoutPassphrase()
                .build();

        PGPPublicKey publicKey = secretKeys.getPublicKey();
        Thread.sleep(1000);
        PGPSignatureGenerator generator = SignatureUtils.getSignatureGeneratorFor(secretKeys.getSecretKey());
        generator.init(SignatureType.CERTIFICATION_REVOCATION.getCode(), secretKeys.getSecretKey().extractPrivateKey(
                new UnprotectedKeysProtector().getDecryptor(secretKeys.getSecretKey().getKeyID())));

        PGPSignature signature = generator.generateCertification("secondary@key.id", publicKey);
        publicKey = PGPPublicKey.addCertification(publicKey, "secondary@key.id", signature);
        PGPPublicKeyRing publicKeys = KeyRingUtils.publicKeyRingFrom(secretKeys);
        publicKeys = PGPPublicKeyRing.insertPublicKey(publicKeys, publicKey);
        secretKeys = PGPSecretKeyRing.replacePublicKeys(secretKeys, publicKeys);

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        List<String> userIds = info.getUserIds();
        assertEquals(Arrays.asList("primary@key.id", "secondary@key.id"), userIds);
        assertTrue(info.isUserIdValid("primary@key.id"));
        assertFalse(info.isUserIdValid("sedondary@key.id"));
        assertFalse(info.isUserIdValid("tertiary@key.id"));
    }
}
