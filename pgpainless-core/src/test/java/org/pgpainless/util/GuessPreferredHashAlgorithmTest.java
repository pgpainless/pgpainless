// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.util;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.CompressionAlgorithm;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.util.OpenPgpKeyAttributeUtil;

public class GuessPreferredHashAlgorithmTest {

    @Test
    public void guessPreferredHashAlgorithmsAssumesHashAlgoUsedBySelfSig() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519),
                                KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                        .overridePreferredHashAlgorithms(new HashAlgorithm[] {})
                        .overridePreferredSymmetricKeyAlgorithms(new SymmetricKeyAlgorithm[] {})
                        .overridePreferredCompressionAlgorithms(new CompressionAlgorithm[] {}))
                .addUserId("test@test.test")
                .build();

        PGPPublicKey publicKey = secretKeys.getPublicKey();
        assertEquals(Collections.emptyList(),
                OpenPgpKeyAttributeUtil.getPreferredHashAlgorithms(publicKey));
        assertEquals(Collections.singletonList(HashAlgorithm.SHA512),
                OpenPgpKeyAttributeUtil.guessPreferredHashAlgorithms(publicKey));
    }
}
