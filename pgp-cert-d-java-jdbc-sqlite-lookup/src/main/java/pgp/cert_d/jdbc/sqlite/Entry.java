// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.jdbc.sqlite;

/**
 * Subkey-ID database entry.
 */
public class Entry {

    private final int id;
    private final String certificate;
    private final long subkeyId;

    public Entry(int id,  long subkeyId, String certificate) {
        this.id = id;
        this.subkeyId = subkeyId;
        this.certificate = certificate;
    }

    /**
     * Get the internal ID of this entry in the database.
     *
     * @return internal id
     */
    public int getId() {
        return id;
    }

    /**
     * Return the key-ID of the subkey.
     *
     * @return subkey id
     */
    public long getSubkeyId() {
        return subkeyId;
    }

    /**
     * Return the fingerprint of the certificate the subkey belongs to.
     * @return fingerprint
     */
    public String getCertificate() {
        return certificate;
    }
}
