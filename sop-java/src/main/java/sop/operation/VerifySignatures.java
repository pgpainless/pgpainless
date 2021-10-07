// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.operation;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import sop.Verification;
import sop.exception.SOPGPException;

public interface VerifySignatures {

    List<Verification> data(InputStream data) throws IOException, SOPGPException.NoSignature, SOPGPException.BadData;
}
