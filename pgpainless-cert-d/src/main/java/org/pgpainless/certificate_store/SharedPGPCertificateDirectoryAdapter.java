// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.certificate_store;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import pgp.cert_d.SharedPGPCertificateDirectory;
import pgp.cert_d.SpecialNames;
import pgp.certificate_store.Certificate;
import pgp.certificate_store.CertificateDirectory;
import pgp.certificate_store.CertificateStore;
import pgp.certificate_store.MergeCallback;
import pgp.certificate_store.SubkeyLookup;
import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;

/**
 * Adapter class used to adapt the {@link SharedPGPCertificateDirectory} for use with
 * {@link CertificateDirectory}.
 */
public class SharedPGPCertificateDirectoryAdapter
        implements CertificateStore {

    private final SharedPGPCertificateDirectory directory;
    private final SubkeyLookup subkeyLookup;

    /**
     * Create an adapter to use {@link SharedPGPCertificateDirectory} objects as {@link CertificateDirectory CertificateStores}.
     *
     * @param directory directory instance
     */
    public SharedPGPCertificateDirectoryAdapter(SharedPGPCertificateDirectory directory, SubkeyLookup subkeyLookup) {
        this.directory = directory;
        this.subkeyLookup = subkeyLookup;
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
        Certificate certificate = directory.insert(data, merge);
        storeIdentifierForSubkeys(certificate);
        return certificate;
    }

    @Override
    public Certificate tryInsertCertificate(InputStream data, MergeCallback merge)
            throws IOException, BadDataException {
        Certificate certificate = directory.tryInsert(data, merge);
        storeIdentifierForSubkeys(certificate);
        return certificate;
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

    private void storeIdentifierForSubkeys(Certificate certificate) throws IOException {
        if (certificate == null) {
            return;
        }
        String fingerprint = certificate.getFingerprint();
        storeCertificateSubkeyIds(fingerprint, new ArrayList<>(certificate.getSubkeyIds()));
    }

    @Override
    public Set<String> getCertificateFingerprintsForSubkeyId(long subkeyId) throws IOException {
        return subkeyLookup.getCertificateFingerprintsForSubkeyId(subkeyId);
    }

    @Override
    public void storeCertificateSubkeyIds(String certificate, List<Long> subkeyIds) throws IOException {
        subkeyLookup.storeCertificateSubkeyIds(certificate, subkeyIds);
    }
}
