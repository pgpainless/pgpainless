// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store;

import java.io.IOException;
import java.util.Set;

public interface SubkeyLookup {

    /**
     * Lookup the fingerprint of the certificate that contains the given subkey.
     * If no record is found, return null.
     *
     * @param subkeyId subkey id
     * @return fingerprint of the certificate
     */
    Set<String> getIdentifiersForSubkeyId(long subkeyId) throws IOException;

    /**
     * Store a record of the subkey id that points to the fingerprint.
     *
     * @param subkeyId subkey id
     * @param identifier fingerprint of the certificate
     */
    void storeIdentifierForSubkeyId(long subkeyId, String identifier) throws IOException;
}
