// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.exception.KeyException;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.xdh.XDHSpec;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.SecretKeyRingProtector;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class GenerateKeyWithoutPrimaryKeyFlagsTest {

    @Test
    public void generateKeyWithoutCertifyKeyFlag_cannotCertifyThirdParties() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.buildKeyRing().setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519)))
                .addSubkey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.SIGN_DATA))
                .addSubkey(KeySpec.getBuilder(KeyType.XDH(XDHSpec._X25519), KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS))
                .addUserId("Alice")
                .build();

        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        assertTrue(info.getValidUserIds().contains("Alice"));

        long primaryKeyId = info.getKeyId();
        assertTrue(info.getKeyFlagsOf("Alice").isEmpty());
        assertTrue(info.getKeyFlagsOf(primaryKeyId).isEmpty());
        assertFalse(info.isUsableForThirdPartyCertification());

        // Key without CERTIFY_OTHER flag cannot be used to certify other keys
        PGPPublicKeyRing thirdPartyCert = TestKeys.getCryptiePublicKeyRing();
        assertThrows(KeyException.UnacceptableThirdPartyCertificationKeyException.class, () ->
                PGPainless.certify().certificate(thirdPartyCert)
                        .withKey(secretKeys, SecretKeyRingProtector.unprotectedKeys()));
    }
}
