// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.operation;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Date;

import sop.exception.SOPGPException;

public interface Verify extends VerifySignatures {

    /**
     * Makes the SOP implementation consider signatures before this date invalid.
     *
     * @param timestamp timestamp
     * @return builder instance
     */
    Verify notBefore(Date timestamp) throws SOPGPException.UnsupportedOption;

    /**
     * Makes the SOP implementation consider signatures after this date invalid.
     *
     * @param timestamp timestamp
     * @return builder instance
     */
    Verify notAfter(Date timestamp) throws SOPGPException.UnsupportedOption;

    /**
     * Adds the verification cert.
     *
     * @param cert input stream containing the encoded cert
     * @return builder instance
     */
    Verify cert(InputStream cert) throws SOPGPException.BadData;

    /**
     * Adds the verification cert.
     *
     * @param cert byte array containing the encoded cert
     * @return builder instance
     */
    default Verify cert(byte[] cert) throws SOPGPException.BadData {
        return cert(new ByteArrayInputStream(cert));
    }

    /**
     * Provides the signatures.
     * @param signatures input stream containing encoded, detached signatures.
     *
     * @return builder instance
     */
    VerifySignatures signatures(InputStream signatures) throws SOPGPException.BadData;

    /**
     * Provides the signatures.
     * @param signatures byte array containing encoded, detached signatures.
     *
     * @return builder instance
     */
    default VerifySignatures signatures(byte[] signatures) throws SOPGPException.BadData {
        return signatures(new ByteArrayInputStream(signatures));
    }

}
