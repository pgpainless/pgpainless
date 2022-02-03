// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store;

import java.io.IOException;

/**
 * Merge a given certificate (update) with an existing certificate.
 */
public interface MergeCallback {

    /**
     * Merge the given certificate data with the existing certificate and return the result.
     *
     * If no existing certificate is found (i.e. existing is null), this method returns the unmodified data.
     *
     * @param data certificate
     * @param existing optional already existing copy of the certificate
     * @return merged certificate
     */
    Certificate merge(Certificate data, Certificate existing) throws IOException;

}
