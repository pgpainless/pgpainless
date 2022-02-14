// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.jdbc.sqlite;

public class Entry {

    private final int id;
    private final String identifier;
    private final long subkeyId;

    public Entry(int id,  long subkeyId, String identifier) {
        this.id = id;
        this.subkeyId = subkeyId;
        this.identifier = identifier;
    }

    public int getId() {
        return id;
    }

    public long getSubkeyId() {
        return subkeyId;
    }

    public String getIdentifier() {
        return identifier;
    }
}
