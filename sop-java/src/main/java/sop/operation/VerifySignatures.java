// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.operation;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import sop.Verification;
import sop.exception.SOPGPException;

public interface VerifySignatures {

    /**
     * Provide the signed data (without signatures).
     *
     * @param data signed data
     * @return list of signature verifications
     * @throws IOException in case of an IO error
     * @throws SOPGPException.NoSignature when no signature is found
     * @throws SOPGPException.BadData when the data is invalid OpenPGP data
     */
    List<Verification> data(InputStream data) throws IOException, SOPGPException.NoSignature, SOPGPException.BadData;

    /**
     * Provide the signed data (without signatures).
     *
     * @param data signed data
     * @return list of signature verifications
     * @throws IOException in case of an IO error
     * @throws SOPGPException.NoSignature when no signature is found
     * @throws SOPGPException.BadData when the data is invalid OpenPGP data
     */
    default List<Verification> data(byte[] data) throws IOException, SOPGPException.NoSignature, SOPGPException.BadData {
        return data(new ByteArrayInputStream(data));
    }
}
