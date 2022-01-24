// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

import pgp.cert_d.exception.BadDataException;
import pgp.cert_d.exception.BadNameException;
import pgp.certificate_store.Certificate;
import pgp.certificate_store.MergeCallback;

public interface SharedPGPCertificateDirectory {

    Certificate get(String fingerprint) throws IOException, BadNameException;

    Certificate get(SpecialName specialName) throws IOException, BadNameException;

    Certificate getIfChanged(String fingerprint, String tag) throws IOException, BadNameException;

    Certificate getIfChanged(SpecialName specialName, String tag) throws IOException, BadNameException;

    Certificate insert(InputStream data, MergeCallback merge) throws IOException, BadDataException, InterruptedException;

    Certificate tryInsert(InputStream data, MergeCallback merge) throws IOException, BadDataException;

    Certificate insertSpecial(SpecialName specialName, InputStream data, MergeCallback merge) throws IOException, BadDataException, BadNameException, InterruptedException;

    Certificate tryInsertSpecial(SpecialName specialName, InputStream data, MergeCallback merge) throws IOException, BadDataException, BadNameException;

    Iterator<Certificate> items();

    Iterator<String> fingerprints();
}
