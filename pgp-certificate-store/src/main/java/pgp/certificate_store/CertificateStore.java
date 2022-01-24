// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

public interface CertificateStore {

    Certificate get(String identifier) throws IOException;

    Certificate getIfChanged(String identifier, String tag) throws IOException;

    Certificate insert(InputStream data, MergeCallback merge) throws IOException;

    Certificate tryInsert(InputStream data, MergeCallback merge) throws IOException;

    Certificate insertSpecial(String specialName, InputStream data, MergeCallback merge) throws IOException;

    Certificate tryInsertSpecial(String specialName, InputStream data, MergeCallback merge) throws IOException;

    Iterator<Certificate> items();

    Iterator<String> fingerprints();
}
