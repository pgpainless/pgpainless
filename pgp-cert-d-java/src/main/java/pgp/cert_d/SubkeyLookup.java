// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

public interface SubkeyLookup {

    /**
     * Lookup the identifier of the certificate that contains the given subkey.
     * If no record is found, return null.
     *
     * @param subkeyId subkey id
     * @return identifier (fingerprint or special name) of the certificate
     */
    String getIdentifierForSubkeyId(long subkeyId);

    /**
     * Store a record of the subkey id that points to the identifier.
     *
     * @param subkeyId subkey id
     * @param identifier fingerprint or special name of the certificate
     */
    void storeIdentifierForSubkeyId(long subkeyId, String identifier);
}
