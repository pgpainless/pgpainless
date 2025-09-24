// SPDX-FileCopyrightText: 2020 Wiktor Kwapisiewicz, 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.util.TestAllImplementations;
import org.pgpainless.util.Passphrase;

/**
 * Reproduce behavior of <a href="https://github.com/pgpainless/pgpainless/issues/16>this issue</a>
 * and verify that the fix is working.
 *
 * The issue is that the implementation of {@link Passphrase#emptyPassphrase()} would set the underlying
 * char array to null, which caused an NPE later on.
 */
public class GenerateWithEmptyPassphraseTest {

    @TestTemplate
    @ExtendWith(TestAllImplementations.class)
    public void testGeneratingKeyWithEmptyPassphraseDoesNotThrow() {

        assertNotNull(PGPainless.buildKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(
                                KeyType.RSA(RsaLength._3072),
                                KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA, KeyFlag.ENCRYPT_COMMS))
                .addUserId("primary@user.id")
                .setPassphrase(Passphrase.emptyPassphrase())
                .build());
    }
}
