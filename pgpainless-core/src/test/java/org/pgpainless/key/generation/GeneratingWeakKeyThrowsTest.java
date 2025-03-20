// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.policy.Policy;

public class GeneratingWeakKeyThrowsTest {

    @Test
    public void refuseToGenerateWeakPrimaryKeyTest() {
        // ensure we have default public key algorithm policy set
        PGPainless.getInstance().setAlgorithmPolicy(new Policy());
        assertThrows(IllegalArgumentException.class, () ->
                PGPainless.buildKeyRing()
                        .setPrimaryKey(KeySpec.getBuilder(KeyType.RSA(RsaLength._1024),
                                KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)));
    }

    @Test
    public void refuseToAddWeakSubkeyDuringGenerationTest() {
        // ensure we have default public key algorithm policy set
        PGPainless.getInstance().setAlgorithmPolicy(new Policy());

        KeyRingBuilder kb = PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.RSA(RsaLength._4096),
                        KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA));

        assertThrows(IllegalArgumentException.class, () ->
                kb.addSubkey(KeySpec.getBuilder(KeyType.RSA(RsaLength._1024),
                        KeyFlag.ENCRYPT_COMMS)));
    }

    @Test
    public void allowToAddWeakKeysWithWeakPolicy() {
        // set a weak algorithm policy
        Map<PublicKeyAlgorithm, Integer> bitStrengths = new HashMap<>();
        bitStrengths.put(PublicKeyAlgorithm.RSA_GENERAL, 512);

        Policy oldPolicy = PGPainless.getPolicy();
        PGPainless.getInstance().setAlgorithmPolicy(oldPolicy.copy()
                .withPublicKeyAlgorithmPolicy(new Policy.PublicKeyAlgorithmPolicy(bitStrengths))
                .build());

        PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.RSA(RsaLength._4096),
                        KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA))
                .addSubkey(KeySpec.getBuilder(KeyType.RSA(RsaLength._1024),
                        KeyFlag.ENCRYPT_COMMS))
                .addUserId("Henry")
                .build();

        // reset public key algorithm policy
        PGPainless.getInstance().setAlgorithmPolicy(oldPolicy);
    }
}
