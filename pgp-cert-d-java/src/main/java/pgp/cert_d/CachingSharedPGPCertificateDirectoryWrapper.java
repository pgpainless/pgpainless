// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;
import pgp.certificate_store.Certificate;
import pgp.certificate_store.MergeCallback;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Caching wrapper for {@link  SharedPGPCertificateDirectory} implementations.
 */
public class CachingSharedPGPCertificateDirectoryWrapper
        implements SharedPGPCertificateDirectory {

    private static final Map<String, String> tagMap = new HashMap<>();
    private static final Map<String, Certificate> certificateMap = new HashMap<>();
    private final SharedPGPCertificateDirectory underlyingCertificateDirectory;

    public CachingSharedPGPCertificateDirectoryWrapper(SharedPGPCertificateDirectory wrapped) {
        this.underlyingCertificateDirectory = wrapped;
    }

    /**
     * Store the given certificate under the given identifier into the cache.
     *
     * @param identifier fingerprint or special name
     * @param certificate certificate
     */
    private void remember(String identifier, Certificate certificate) {
        certificateMap.put(identifier, certificate);
        try {
            tagMap.put(identifier, certificate.getTag());
        } catch (IOException e) {
            tagMap.put(identifier, null);
        }
    }

    /**
     * Returns true, if the cached tag differs from the provided tag.
     *
     * @param identifier fingerprint or special name
     * @param tag tag
     * @return true if cached tag differs, false otherwise
     */
    private boolean tagChanged(String identifier, String tag) {
        String tack = tagMap.get(identifier);
        return !tagEquals(tag, tack);
    }

    /**
     * Return true, if tag and tack are equal, false otherwise.
     * @param tag tag
     * @param tack other tag
     * @return true if equal
     */
    private static boolean tagEquals(String tag, String tack) {
        return (tag == null && tack == null)
                || tag != null && tag.equals(tack);
    }

    /**
     * Clear the cache.
     */
    public void invalidate() {
        certificateMap.clear();
        tagMap.clear();
    }

    @Override
    public LockingMechanism getLock() {
        return underlyingCertificateDirectory.getLock();
    }

    @Override
    public Certificate getByFingerprint(String fingerprint)
            throws IOException, BadNameException, BadDataException {
        Certificate certificate = certificateMap.get(fingerprint);
        if (certificate == null) {
            certificate = underlyingCertificateDirectory.getByFingerprint(fingerprint);
            if (certificate != null) {
                remember(fingerprint, certificate);
            }
        }

        return certificate;
    }

    @Override
    public Certificate getBySpecialName(String specialName)
            throws IOException, BadNameException, BadDataException {
        Certificate certificate = certificateMap.get(specialName);
        if (certificate == null) {
            certificate = underlyingCertificateDirectory.getBySpecialName(specialName);
            if (certificate != null) {
                remember(specialName, certificate);
            }
        }

        return certificate;
    }

    @Override
    public Certificate getByFingerprintIfChanged(String fingerprint, String tag)
            throws IOException, BadNameException, BadDataException {
        if (tagChanged(fingerprint, tag)) {
            return getByFingerprint(fingerprint);
        }
        return null;
    }

    @Override
    public Certificate getBySpecialNameIfChanged(String specialName, String tag)
            throws IOException, BadNameException, BadDataException {
        if (tagChanged(specialName, tag)) {
            return getBySpecialName(specialName);
        }
        return null;
    }

    @Override
    public Certificate insert(InputStream data, MergeCallback merge)
            throws IOException, BadDataException, InterruptedException {
        Certificate certificate = underlyingCertificateDirectory.insert(data, merge);
        remember(certificate.getFingerprint(), certificate);
        return certificate;
    }

    @Override
    public Certificate tryInsert(InputStream data, MergeCallback merge)
            throws IOException, BadDataException {
        Certificate certificate = underlyingCertificateDirectory.tryInsert(data, merge);
        if (certificate != null) {
            remember(certificate.getFingerprint(), certificate);
        }
        return certificate;
    }

    @Override
    public Certificate insertWithSpecialName(String specialName, InputStream data, MergeCallback merge)
            throws IOException, BadDataException, BadNameException, InterruptedException {
        Certificate certificate = underlyingCertificateDirectory.insertWithSpecialName(specialName, data, merge);
        remember(specialName, certificate);
        return certificate;
    }

    @Override
    public Certificate tryInsertWithSpecialName(String specialName, InputStream data, MergeCallback merge)
            throws IOException, BadDataException, BadNameException {
        Certificate certificate = underlyingCertificateDirectory.tryInsertWithSpecialName(specialName, data, merge);
        if (certificate != null) {
            remember(specialName, certificate);
        }
        return certificate;
    }

    @Override
    public Iterator<Certificate> items() {

        Iterator<Certificate> iterator = underlyingCertificateDirectory.items();

        return new Iterator<Certificate>() {
            @Override
            public boolean hasNext() {
                return iterator.hasNext();
            }

            @Override
            public Certificate next() {
                Certificate certificate = iterator.next();
                remember(certificate.getFingerprint(), certificate);
                return certificate;
            }
        };
    }

    @Override
    public Iterator<String> fingerprints() {
        return underlyingCertificateDirectory.fingerprints();
    }

}
