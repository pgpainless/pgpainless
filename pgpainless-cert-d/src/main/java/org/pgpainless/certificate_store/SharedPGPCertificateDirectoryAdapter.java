// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.certificate_store;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

import pgp.cert_d.SharedPGPCertificateDirectory;
import pgp.cert_d.SpecialNames;
import pgp.certificate_store.Certificate;
import pgp.certificate_store.CertificateStore;
import pgp.certificate_store.MergeCallback;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;

/**
 * Adapter class used to adapt the {@link SharedPGPCertificateDirectory} for use with
 * {@link CertificateStore}.
 */
public class SharedPGPCertificateDirectoryAdapter
        implements CertificateStore {

    private final SharedPGPCertificateDirectory directory;

    /**
     * Create an adapter to use {@link SharedPGPCertificateDirectory} objects as {@link CertificateStore CertificateStores}.
     *
     * @param directory directory instance
     */
    public SharedPGPCertificateDirectoryAdapter(SharedPGPCertificateDirectory directory) {
        this.directory = directory;
    }

    @Override
    public Certificate getCertificate(String identifier)
            throws IOException, BadDataException, BadNameException {
        String specialName = SpecialNames.lookupSpecialName(identifier);
        if (specialName != null) {
            return directory.getBySpecialName(specialName);
        }

        return directory.getByFingerprint(identifier);

    }

    @Override
    public Certificate getCertificateIfChanged(String identifier, String tag)
            throws IOException, BadDataException, BadNameException {
        String specialName = SpecialNames.lookupSpecialName(identifier);
        if (specialName != null) {
            return directory.getBySpecialNameIfChanged(specialName, tag);
        }

        return directory.getByFingerprintIfChanged(identifier, tag);

    }

    @Override
    public Certificate insertCertificate(InputStream data, MergeCallback merge)
            throws IOException, InterruptedException, BadDataException {
        return directory.insert(data, merge);
    }

    @Override
    public Certificate tryInsertCertificate(InputStream data, MergeCallback merge)
            throws IOException, BadDataException {
        return directory.tryInsert(data, merge);
    }

    @Override
    public Certificate insertCertificateBySpecialName(String specialName, InputStream data, MergeCallback merge)
            throws IOException, InterruptedException, BadDataException, BadNameException {
        return directory.insertWithSpecialName(specialName, data, merge);
    }

    @Override
    public Certificate tryInsertCertificateBySpecialName(String specialName, InputStream data, MergeCallback merge)
            throws IOException, BadDataException, BadNameException {
        return directory.tryInsertWithSpecialName(specialName, data, merge);
    }

    @Override
    public Iterator<Certificate> getCertificates() {
        return directory.items();
    }

    @Override
    public Iterator<String> getFingerprints() {
        return directory.fingerprints();
    }
}
