// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

/**
 * Certificate storage definition.
 * This interface defines methods to insert and retrieve {@link Certificate Certificates} to and from a store.
 *
 * {@link Certificate Certificates} are hereby identified by identifiers. An identifier can either be a fingerprint
 * or a special name. Special names are implementation-defined identifiers for certificates.
 *
 * Fingerprints are expected to be hexadecimal lowercase character sequences.
 */
public interface CertificateStore {

    /**
     * Return the certificate that matches the given identifier.
     * If no matching certificate can be found, return null.
     *
     * @param identifier identifier for a certificate.
     * @return certificate or null
     *
     * @throws IOException in case of an IO-error
     */
    Certificate getCertificate(String identifier) throws IOException;

    /**
     *
     * @param identifier
     * @param tag
     * @return
     * @throws IOException
     */
    Certificate getCertificateIfChanged(String identifier, String tag) throws IOException;

    Certificate insertCertificate(InputStream data, MergeCallback merge) throws IOException, InterruptedException;

    Certificate tryInsertCertificate(InputStream data, MergeCallback merge) throws IOException;

    Certificate insertCertificateBySpecialName(String specialName, InputStream data, MergeCallback merge) throws IOException, InterruptedException;

    Certificate tryInsertCertificateBySpecialName(String specialName, InputStream data, MergeCallback merge) throws IOException;

    Iterator<Certificate> getCertificates();

    Iterator<String> getFingerprints();
}
