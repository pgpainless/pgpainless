// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.jdbc.sqlite;

import java.sql.SQLException;
import java.util.List;

public interface SubkeyLookupDao {

    int insertValues(String certificate, List<Long> subkeyIds) throws SQLException;

    List<Entry> selectValues(long subkeyId) throws SQLException;
}
