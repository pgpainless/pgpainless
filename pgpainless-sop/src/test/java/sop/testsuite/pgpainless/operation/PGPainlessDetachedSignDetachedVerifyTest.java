// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.testsuite.pgpainless.operation;

import sop.SOP;
import sop.testsuite.operation.DetachedSignDetachedVerifyTest;

import java.io.IOException;

public class PGPainlessDetachedSignDetachedVerifyTest extends DetachedSignDetachedVerifyTest {

    @Override
    public void verifyMissingCertCausesMissingArg(SOP sop) {
        super.verifyMissingCertCausesMissingArg(sop);
    }

    @Override
    public void signVerifyWithCarolKey(SOP sop) throws IOException {
        super.signVerifyWithCarolKey(sop);
    }
}
