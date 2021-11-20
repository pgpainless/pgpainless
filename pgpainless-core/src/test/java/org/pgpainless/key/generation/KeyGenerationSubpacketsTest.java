// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.info.KeyRingInfo;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class KeyGenerationSubpacketsTest {

    @Test
    public void verifyDefaultSubpackets()
            throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing().modernKeyRing("Alice", null);
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);

        PGPSignature userIdSig = info.getLatestUserIdCertification("Alice");
        assertNotNull(userIdSig);
        assertNotNull(userIdSig.getHashedSubPackets().getIssuerFingerprint());

    }
}
