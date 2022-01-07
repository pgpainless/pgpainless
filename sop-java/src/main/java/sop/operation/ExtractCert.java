// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.operation;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import sop.Ready;
import sop.exception.SOPGPException;

public interface ExtractCert {

    /**
     * Disable ASCII armor encoding.
     *
     * @return builder instance
     */
    ExtractCert noArmor();

    /**
     * Extract the cert(s) from the provided key(s).
     *
     * @param keyInputStream input stream containing the encoding of one or more OpenPGP keys
     * @return result containing the encoding of the keys certs
     */
    Ready key(InputStream keyInputStream) throws IOException, SOPGPException.BadData;

    /**
     * Extract the cert(s) from the provided key(s).
     *
     * @param key byte array containing the encoding of one or more OpenPGP key
     * @return result containing the encoding of the keys certs
     */
    default Ready key(byte[] key) throws IOException, SOPGPException.BadData {
        return key(new ByteArrayInputStream(key));
    }
}
