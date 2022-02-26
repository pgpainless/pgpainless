// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.jdbc.sqlite;

import org.sqlite.SQLiteErrorCode;
import org.sqlite.SQLiteException;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class SqliteSubkeyLookupDaoImpl implements SubkeyLookupDao {

    private final String databaseUrl;

    private static final String CREATE_TABLE_STMT = "" +
            "CREATE TABLE IF NOT EXISTS subkey_lookup (\n" +
            "  id integer PRIMARY KEY,\n" +         // id (internal to the database)
            "  certificate text NOT NULL,\n" +      // certificate fingerprint
            "  subkey_id integer NOT NULL,\n" +     // subkey id
            "  UNIQUE(certificate, subkey_id)\n" +
            ")";

    private static final String INSERT_STMT = "" +
            "INSERT INTO subkey_lookup(certificate, subkey_id) " +
            "VALUES (?,?)";
    private static final String QUERY_STMT = "" +
            "SELECT * FROM subkey_lookup " +
            "WHERE subkey_id=?";

    public SqliteSubkeyLookupDaoImpl(String databaseURL) throws SQLException {
        this.databaseUrl = databaseURL;
        try (Connection connection = getConnection(); Statement statement = connection.createStatement()) {
            statement.execute(CREATE_TABLE_STMT);
        }
    }

    public Connection getConnection() throws SQLException {
        return DriverManager.getConnection(databaseUrl);
    }

    public static SqliteSubkeyLookupDaoImpl forDatabaseFile(File databaseFile) throws SQLException {
        return new SqliteSubkeyLookupDaoImpl("jdbc:sqlite:" + databaseFile.getAbsolutePath());
    }

    public int insertValues(String certificate, List<Long> subkeyIds) throws SQLException {
        int inserted = 0;
        try (Connection connection = getConnection(); PreparedStatement statement = connection.prepareStatement(INSERT_STMT)) {
            for (long subkeyId : subkeyIds) {
                try {
                    statement.setString(1, certificate);
                    statement.setLong(2, subkeyId);
                    statement.executeUpdate();
                    inserted++;
                } catch (SQLiteException e) {
                    // throw any exception, except:
                    // ignore unique constraint-related exceptions if we ignoreDuplicates
                    if (e.getResultCode().code == SQLiteErrorCode.SQLITE_CONSTRAINT_UNIQUE.code) {
                        // ignore duplicates
                    } else {
                        throw e;
                    }
                }
            }
        }
        return inserted;
    }

    public List<Entry> selectValues(long subkeyId) throws SQLException {
        List<Entry> results = new ArrayList<>();
        try (Connection connection = getConnection(); PreparedStatement statement = connection.prepareStatement(QUERY_STMT)) {
            statement.setLong(1, subkeyId);
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    Entry entry = new Entry(
                            resultSet.getInt("id"),
                            resultSet.getLong("subkey_id"),
                            resultSet.getString("certificate"));
                    results.add(entry);
                }
            }
        }
        return results;
    }
}
