// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.testsuite.pgpainless.operation;

import java.io.IOException;

import org.junit.jupiter.api.Disabled;
import sop.SOP;
import sop.testsuite.operation.ExtractCertTest;

public class PGPainlessExtractCertTest extends ExtractCertTest {

    @Disabled("BC uses old CTBs causing mismatching byte arrays :/")
    @Override
    public void extractAliceCertFromAliceKeyTest(SOP sop) throws IOException {
        super.extractAliceCertFromAliceKeyTest(sop);
    }

    @Disabled("BC uses old CTBs causing mismatching byte arrays :/")
    @Override
    public void extractBobsCertFromBobsKeyTest(SOP sop) throws IOException {
        super.extractBobsCertFromBobsKeyTest(sop);
    }

    @Disabled("BC uses old CTBs causing mismatching byte arrays :/")
    @Override
    public void extractCarolsCertFromCarolsKeyTest(SOP sop) throws IOException {
        super.extractCarolsCertFromCarolsKeyTest(sop);
    }
}
