// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.operation;

import java.io.IOException;
import java.io.InputStream;

import sop.ReadyWithResult;
import sop.Signatures;

public interface DetachInbandSignatureAndMessage {

    DetachInbandSignatureAndMessage noArmor();

    ReadyWithResult<Signatures> message(InputStream messageInputStream) throws IOException;

}
