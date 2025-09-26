// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.testsuite.pgpainless.operation;

import java.io.IOException;

import sop.SOP;
import sop.testsuite.operation.ExtractCertTest;

public class PGPainlessExtractCertTest extends ExtractCertTest {

    @Override
    public void extractAliceCertFromAliceKeyTest(SOP sop) throws IOException {
        super.extractAliceCertFromAliceKeyTest(sop);
    }

    @Override
    public void extractBobsCertFromBobsKeyTest(SOP sop) throws IOException {
        super.extractBobsCertFromBobsKeyTest(sop);
    }

    @Override
    public void extractCarolsCertFromCarolsKeyTest(SOP sop) throws IOException {
        super.extractCarolsCertFromCarolsKeyTest(sop);
    }
}
