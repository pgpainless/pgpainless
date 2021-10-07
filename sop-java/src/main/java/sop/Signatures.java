// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop;

import java.io.IOException;
import java.io.OutputStream;

public abstract class Signatures extends Ready {

    /**
     * Write OpenPGP signatures to the provided output stream.
     *
     * @param signatureOutputStream output stream
     * @throws IOException in case of an IO error
     */
    @Override
    public abstract void writeTo(OutputStream signatureOutputStream) throws IOException;

}
