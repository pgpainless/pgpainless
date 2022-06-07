// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.sop;

import sop.ReadyWithResult;
import sop.SigningResult;
import sop.enums.InlineSignAs;
import sop.exception.SOPGPException;
import sop.operation.DetachedSign;
import sop.operation.InlineSign;

import java.io.IOException;
import java.io.InputStream;

public class InlineSignImpl implements InlineSign {
    @Override
    public DetachedSign mode(InlineSignAs mode) throws SOPGPException.UnsupportedOption {
        return null;
    }

    @Override
    public DetachedSign noArmor() {
        return null;
    }

    @Override
    public InlineSign key(InputStream key) throws SOPGPException.KeyIsProtected, SOPGPException.BadData, IOException {
        return null;
    }

    @Override
    public InlineSign withKeyPassword(byte[] password) {
        return null;
    }

    @Override
    public ReadyWithResult<SigningResult> data(InputStream data) throws IOException, SOPGPException.ExpectedText {
        return null;
    }
}
