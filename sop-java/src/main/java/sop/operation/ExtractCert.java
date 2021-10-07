// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.operation;

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
     * Extract the cert from the provided key.
     *
     * @param keyInputStream input stream containing the encoding of an OpenPGP key
     * @return input stream containing the encoding of the keys cert
     */
    Ready key(InputStream keyInputStream) throws IOException, SOPGPException.BadData;
}
