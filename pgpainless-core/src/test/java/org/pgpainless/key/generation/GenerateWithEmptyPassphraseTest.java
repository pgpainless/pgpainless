// SPDX-FileCopyrightText: 2020 Wiktor Kwapisiewicz, 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.util.Passphrase;

/**
 * Reproduce behavior of https://github.com/pgpainless/pgpainless/issues/16
 * and verify that the fix is working.
 *
 * The issue is that the implementation of {@link Passphrase#emptyPassphrase()} would set the underlying
 * char array to null, which caused an NPE later on.
 */
public class GenerateWithEmptyPassphraseTest {

    @ParameterizedTest
    @MethodSource("org.pgpainless.util.TestImplementationFactoryProvider#provideImplementationFactories")
    public void testGeneratingKeyWithEmptyPassphraseDoesNotThrow(ImplementationFactory implementationFactory) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, IOException {
        ImplementationFactory.setFactoryImplementation(implementationFactory);

        assertNotNull(PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(
                                KeyType.RSA(RsaLength._3072),
                                KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA, KeyFlag.ENCRYPT_COMMS))
                .addUserId("primary@user.id")
                .setPassphrase(Passphrase.emptyPassphrase())
                .build());
    }
}
