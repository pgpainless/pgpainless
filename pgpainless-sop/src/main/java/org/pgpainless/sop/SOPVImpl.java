// SPDX-FileCopyrightText: 2024 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import org.jetbrains.annotations.NotNull;
import org.pgpainless.util.ArmoredOutputStreamFactory;
import sop.SOPV;
import sop.operation.DetachedVerify;
import sop.operation.InlineVerify;
import sop.operation.Version;

/**
 * Implementation of the <pre>sopv</pre> interface subset using PGPainless.
 */
public class SOPVImpl implements SOPV {

    static {
        ArmoredOutputStreamFactory.setVersionInfo(null);
    }

    @NotNull
    @Override
    public DetachedVerify detachedVerify() {
        return new DetachedVerifyImpl();
    }

    @NotNull
    @Override
    public InlineVerify inlineVerify() {
        return new InlineVerifyImpl();
    }

    @NotNull
    @Override
    public Version version() {
        return new VersionImpl();
    }
}
