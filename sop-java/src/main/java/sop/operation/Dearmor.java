// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.operation;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import sop.Ready;
import sop.exception.SOPGPException;

public interface Dearmor {

    /**
     * Dearmor armored OpenPGP data.
     *
     * @param data armored OpenPGP data
     * @return input stream of unarmored data
     */
    Ready data(InputStream data) throws SOPGPException.BadData, IOException;

    /**
     * Dearmor armored OpenPGP data.
     *
     * @param data armored OpenPGP data
     * @return input stream of unarmored data
     */
    default Ready data(byte[] data) throws SOPGPException.BadData, IOException {
        return data(new ByteArrayInputStream(data));
    }
}
