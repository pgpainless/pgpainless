// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package sop.operation;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import sop.Ready;
import sop.enums.ArmorLabel;
import sop.exception.SOPGPException;

public interface Armor {

    /**
     * Overrides automatic detection of label.
     *
     * @param label armor label
     * @return builder instance
     */
    Armor label(ArmorLabel label) throws SOPGPException.UnsupportedOption;

    /**
     * Armor the provided data.
     *
     * @param data input stream of unarmored OpenPGP data
     * @return armored data
     */
    Ready data(InputStream data) throws SOPGPException.BadData;

    /**
     * Armor the provided data.
     *
     * @param data unarmored OpenPGP data
     * @return armored data
     */
    default Ready data(byte[] data) throws SOPGPException.BadData {
        return data(new ByteArrayInputStream(data));
    }
}
