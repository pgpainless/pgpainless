// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.testsuite.pgpainless.operation;

import org.junit.jupiter.api.Disabled;
import sop.SOP;
import sop.testsuite.operation.InlineSignInlineVerifyTest;

import java.io.IOException;

public class PGPainlessInlineSignInlineVerifyTest extends InlineSignInlineVerifyTest {

    @Override
    @Disabled("Carol is an ElGamal key, which is no longer supported.")
    public void inlineSignVerifyCarol(SOP sop) throws IOException {
        super.inlineSignVerifyCarol(sop);
    }
}
