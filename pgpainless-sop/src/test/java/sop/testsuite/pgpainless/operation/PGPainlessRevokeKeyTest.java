// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.testsuite.pgpainless.operation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pgpainless.PGPainless;
import org.pgpainless.key.info.KeyRingInfo;
import sop.SOP;
import sop.testsuite.operation.RevokeKeyTest;

public class PGPainlessRevokeKeyTest extends RevokeKeyTest {

    @ParameterizedTest
    @MethodSource("provideInstances") // from sop-java's RevokeKeyTest class
    @Override
    public void revokeUnprotectedKey(SOP sop) throws IOException {
        super.revokeUnprotectedKey(sop);

        byte[] key = sop.generateKey().generate().getBytes();
        byte[] revokedKey = sop.revokeKey().keys(key).getBytes();

        PGPKeyRing certificate = PGPainless.readKeyRing().keyRing(revokedKey);
        assertFalse(certificate instanceof PGPSecretKeyRing);
        assertTrue(certificate instanceof PGPPublicKeyRing);

        KeyRingInfo info = PGPainless.inspectKeyRing(certificate);
        assertTrue(info.getRevocationState().isSoftRevocation());
    }
}
