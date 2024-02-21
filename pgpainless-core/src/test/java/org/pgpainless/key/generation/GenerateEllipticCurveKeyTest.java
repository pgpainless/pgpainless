// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve;
import org.pgpainless.key.generation.type.xdh.XDHSpec;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnlockSecretKey;
import org.pgpainless.key.util.UserId;
import org.pgpainless.util.TestAllImplementations;

public class GenerateEllipticCurveKeyTest {

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void generateEllipticCurveKeys()
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        PGPSecretKeyRing keyRing = PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(
                        KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519),
                        KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA))
                .addSubkey(KeySpec.getBuilder(KeyType.XDH(XDHSpec._X25519), KeyFlag.ENCRYPT_COMMS))
                .addUserId(UserId.onlyEmail("alice@wonderland.lit").toString())
                .build();

        assertEquals(PublicKeyAlgorithm.EDDSA_LEGACY.getAlgorithmId(), keyRing.getPublicKey().getAlgorithm());
        UnlockSecretKey.unlockSecretKey(keyRing.getSecretKey(), SecretKeyRingProtector.unprotectedKeys());
    }
}
