// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.operation;

import java.io.IOException;
import java.io.InputStream;

import sop.Ready;
import sop.enums.SignAs;
import sop.exception.SOPGPException;

public interface Sign {

    /**
     * Disable ASCII armor encoding.
     *
     * @return builder instance
     */
    Sign noArmor();

    /**
     * Sets the signature mode.
     * Note: This method has to be called before {@link #key(InputStream)} is called.
     *
     * @param mode signature mode
     * @return builder instance
     */
    Sign mode(SignAs mode) throws SOPGPException.UnsupportedOption;

    /**
     * Adds the signer key.
     *
     * @param key input stream containing encoded key
     * @return builder instance
     */
    Sign key(InputStream key) throws SOPGPException.KeyIsProtected, SOPGPException.BadData, IOException;

    /**
     * Signs data.
     *
     * @param data input stream containing data
     * @return ready
     */
    Ready data(InputStream data) throws IOException, SOPGPException.ExpectedText;
}
