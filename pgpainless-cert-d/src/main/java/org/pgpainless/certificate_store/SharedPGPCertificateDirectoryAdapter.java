// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.certificate_store;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

import pgp.cert_d.SharedPGPCertificateDirectory;
import pgp.cert_d.SpecialNames;
import pgp.cert_d.exception.BadDataException;
import pgp.cert_d.exception.BadNameException;
import pgp.certificate_store.Certificate;
import pgp.certificate_store.CertificateStore;
import pgp.certificate_store.MergeCallback;

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
            throws IOException {
        String specialName = SpecialNames.lookupSpecialName(identifier);
        if (specialName != null) {
            try {
                return directory.getBySpecialName(specialName);
            } catch (BadNameException e) {
                throw new IllegalArgumentException("Unknown special name " + identifier, e);
            }
        }

        try {
            return directory.getByFingerprint(identifier);
        } catch (BadNameException e) {
            throw new IllegalArgumentException("Invalid fingerprint " + identifier, e);
        } catch (BadDataException e) {
            throw new IOException("Bad data.", e);
        }
    }

    @Override
    public Certificate getCertificateIfChanged(String identifier, String tag)
            throws IOException {
        String specialName = SpecialNames.lookupSpecialName(identifier);
        if (specialName != null) {
            try {
                return directory.getBySpecialNameIfChanged(specialName, tag);
            } catch (BadNameException e) {
                throw new IllegalArgumentException("Unknown special name " + identifier, e);
            }
        }

        try {
            return directory.getByFingerprintIfChanged(identifier, tag);
        } catch (BadNameException e) {
            throw new IllegalArgumentException("Invalid fingerprint " + identifier, e);
        } catch (BadDataException e) {
            throw new IOException("Bad data.", e);
        }
    }

    @Override
    public Certificate insertCertificate(InputStream data, MergeCallback merge)
            throws IOException, InterruptedException {
        try {
            return directory.insert(data, merge);
        } catch (BadDataException e) {
            throw new IOException("Cannot insert certificate due to bad data", e);
        }
    }

    @Override
    public Certificate tryInsertCertificate(InputStream data, MergeCallback merge)
            throws IOException {
        try {
            return directory.tryInsert(data, merge);
        } catch (BadDataException e) {
            throw new IOException("Cannot insert certificate due to bad data", e);
        }
    }

    @Override
    public Certificate insertCertificateBySpecialName(String specialName, InputStream data, MergeCallback merge)
            throws IOException, InterruptedException {
        try {
            String specialNameValidated = SpecialNames.lookupSpecialName(specialName);
            if (specialNameValidated == null) {
                throw new IllegalArgumentException("Unknown special name " + specialName);
            }

            return directory.insertWithSpecialName(specialNameValidated, data, merge);
        } catch (BadNameException e) {
            throw new IllegalArgumentException("Unknown special name " + specialName);
        } catch (BadDataException e) {
            throw new IOException("Cannot insert certificate due to bad data", e);
        }
    }

    @Override
    public Certificate tryInsertCertificateBySpecialName(String specialName, InputStream data, MergeCallback merge)
            throws IOException {
        try {
            String specialNameValidated = SpecialNames.lookupSpecialName(specialName);
            if (specialNameValidated == null) {
                throw new IllegalArgumentException("Unknown special name " + specialName);
            }

            return directory.tryInsertWithSpecialName(specialNameValidated, data, merge);
        } catch (BadNameException e) {
            throw new IllegalArgumentException("Unknown special name " + specialName);
        } catch (BadDataException e) {
            throw new IOException("Cannot insert certificate due to bad data", e);
        }
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
