// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import sop.ReadyWithResult;
import sop.Verification;
import sop.exception.SOPGPException;
import sop.operation.InlineVerify;

import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.List;

public class InlineVerifyImpl implements InlineVerify {
    @Override
    public ReadyWithResult<List<Verification>> data(InputStream data) throws IOException, SOPGPException.NoSignature, SOPGPException.BadData {
        return null;
    }

    @Override
    public InlineVerify notBefore(Date timestamp) throws SOPGPException.UnsupportedOption {
        return null;
    }

    @Override
    public InlineVerify notAfter(Date timestamp) throws SOPGPException.UnsupportedOption {
        return null;
    }

    @Override
    public InlineVerify cert(InputStream cert) throws SOPGPException.BadData {
        return null;
    }
}
