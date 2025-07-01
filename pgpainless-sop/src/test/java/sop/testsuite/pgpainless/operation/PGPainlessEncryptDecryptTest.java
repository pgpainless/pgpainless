// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.testsuite.pgpainless.operation;

import org.pgpainless.PGPainless;
import org.pgpainless.policy.Policy;
import sop.SOP;
import sop.testsuite.operation.EncryptDecryptTest;

import java.io.IOException;

public class PGPainlessEncryptDecryptTest extends EncryptDecryptTest {

    @Override
    public void encryptDecryptRoundTripCarolTest(SOP sop) throws IOException {
        // Carols key is DSA, which is rejected by PGPainless default policy now.
        // Therefore, we need to set a relaxed PGPainless API instance, allowing DSA keys.
        PGPainless strictAPI = PGPainless.getInstance();
        PGPainless relaxedAPI = new PGPainless(
                strictAPI.getImplementation(),
                strictAPI.getAlgorithmPolicy().copy()
                        .withPublicKeyAlgorithmPolicy(Policy.PublicKeyAlgorithmPolicy.bsi2021PublicKeyAlgorithmPolicy())
                        .build());
        PGPainless.setInstance(relaxedAPI);

        super.encryptDecryptRoundTripCarolTest(sop);

        PGPainless.setInstance(strictAPI);
    }

}
