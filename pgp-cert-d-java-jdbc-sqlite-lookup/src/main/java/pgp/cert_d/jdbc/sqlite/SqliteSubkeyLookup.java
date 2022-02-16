// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.jdbc.sqlite;

import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.sqlite.SQLiteErrorCode;
import org.sqlite.SQLiteException;
import pgp.certificate_store.SubkeyLookup;

public class SqliteSubkeyLookup implements SubkeyLookup {

    private final String databaseUrl;

    private static final String CREATE_TABLE_STMT = "" +
            "CREATE TABLE IF NOT EXISTS subkey_lookup (\n" +
            "  id integer PRIMARY KEY,\n" +
            "  identifier text NOT NULL,\n" +
            "  subkey_id integer NOT NULL,\n" +
            "  UNIQUE(identifier, subkey_id)\n" +
            ")";

    private static final String INSERT_STMT = "" +
            "INSERT INTO subkey_lookup(identifier, subkey_id) VALUES (?,?)";
    private static final String QUERY_STMT = "" +
            "SELECT * FROM subkey_lookup WHERE subkey_id=?";

    public SqliteSubkeyLookup(String databaseURL) throws SQLException {
        this.databaseUrl = databaseURL;
        try (Connection connection = getConnection(); Statement statement = connection.createStatement()) {
            statement.execute(CREATE_TABLE_STMT);
        }
    }

    public Connection getConnection() throws SQLException {
        return DriverManager.getConnection(databaseUrl);
    }

    public static SqliteSubkeyLookup forDatabaseFile(File databaseFile) throws SQLException {
        return new SqliteSubkeyLookup("jdbc:sqlite:" + databaseFile.getAbsolutePath());
    }

    public void insert(long subkeyId, String identifier, boolean ignoreDuplicates) throws SQLException {
        try (Connection connection = getConnection(); PreparedStatement statement = connection.prepareStatement(INSERT_STMT)) {
            statement.setString(1, identifier);
            statement.setLong(2, subkeyId);
            statement.executeUpdate();
        } catch (SQLiteException e) {
            // throw any exception, except:
            // ignore unique constraint-related exceptions if we ignoreDuplicates
            if (!ignoreDuplicates || e.getResultCode().code != SQLiteErrorCode.SQLITE_CONSTRAINT_UNIQUE.code) {
                throw e;
            }
        }
    }

    public List<Entry> get(long subkeyId) throws SQLException {
        List<Entry> results = new ArrayList<>();
        try (Connection connection = getConnection(); PreparedStatement statement = connection.prepareStatement(QUERY_STMT)) {
            statement.setLong(1, subkeyId);
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    Entry entry = new Entry(
                            resultSet.getInt("id"),
                            resultSet.getLong("subkey_id"),
                            resultSet.getString("identifier"));
                    results.add(entry);
                }
            }
        }
        return results;
    }

    @Override
    public Set<String> getIdentifiersForSubkeyId(long subkeyId) throws IOException {
        try {
            List<Entry> entries = get(subkeyId);
            Set<String> identifiers = new HashSet<>();
            for (Entry entry : entries) {
                identifiers.add(entry.getIdentifier());
            }

            return Collections.unmodifiableSet(identifiers);
        } catch (SQLException e) {
            throw new IOException("Cannot query for subkey lookup entries.", e);
        }
    }

    @Override
    public void storeIdentifierForSubkeyId(long subkeyId, String identifier)
            throws IOException {
        try {
            insert(subkeyId, identifier, true);
        } catch (SQLException e) {
            throw new IOException("Cannot store subkey lookup entry in database.", e);
        }
    }
}
