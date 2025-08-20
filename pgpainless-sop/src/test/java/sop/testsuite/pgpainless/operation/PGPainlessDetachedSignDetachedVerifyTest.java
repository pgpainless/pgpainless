// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.testsuite.pgpainless.operation;

import org.junit.jupiter.api.Disabled;
import sop.SOP;
import sop.testsuite.operation.DetachedSignDetachedVerifyTest;

import java.io.IOException;

public class PGPainlessDetachedSignDetachedVerifyTest extends DetachedSignDetachedVerifyTest {

    @Override
    @Disabled("Since we allow for dynamic cert loading, we can ignore this test")
    public void verifyMissingCertCausesMissingArg(SOP sop) {
        super.verifyMissingCertCausesMissingArg(sop);
    }

    @Override
    @Disabled("Carol is an ElGamal key, which are no longer supported.")
    public void signVerifyWithCarolKey(SOP sop) throws IOException {
        super.signVerifyWithCarolKey(sop);
    }
}
