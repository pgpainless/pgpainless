// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.jdbc.sqlite;

import java.io.IOException;
import java.sql.SQLException;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import pgp.certificate_store.SubkeyLookup;

public class DatabaseSubkeyLookup implements SubkeyLookup {

    private final SubkeyLookupDao dao;

    public DatabaseSubkeyLookup(SubkeyLookupDao dao) {
        this.dao = dao;
    }

    @Override
    public Set<String> getCertificateFingerprintsForSubkeyId(long subkeyId) throws IOException {
        try {
            List<Entry> entries = dao.selectValues(subkeyId);
            Set<String> certificates = new HashSet<>();
            for (Entry entry : entries) {
                certificates.add(entry.getCertificate());
            }

            return Collections.unmodifiableSet(certificates);
        } catch (SQLException e) {
            throw new IOException("Cannot query for subkey lookup entries.", e);
        }
    }

    @Override
    public void storeCertificateSubkeyIds(String certificate, List<Long> subkeyIds) throws IOException {
        try {
            dao.insertValues(certificate, subkeyIds);
        } catch (SQLException e) {
            throw new IOException("Cannot store subkey lookup entries in database.", e);
        }
    }
}
