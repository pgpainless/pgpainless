// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store;

import java.io.IOException;
import java.util.List;
import java.util.Set;

public interface SubkeyLookup {

    /**
     * Lookup the fingerprint of the certificate that contains the given subkey.
     * If no record is found, return null.
     *
     * @param subkeyId subkey id
     * @return fingerprint of the certificate
     */
    Set<String> getCertificateFingerprintsForSubkeyId(long subkeyId) throws IOException;

    /**
     * Record, which certificate the subkey-ids in the list belong to.
     * This method does not change the affiliation of subkey-ids not contained in the provided list.
     *
     * @param certificate certificate fingerprint
     * @param subkeyIds subkey ids
     * @throws IOException in case of an IO error
     */
    void storeCertificateSubkeyIds(String certificate, List<Long> subkeyIds) throws IOException;
}
