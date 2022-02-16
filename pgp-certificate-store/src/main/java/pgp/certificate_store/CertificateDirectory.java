// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.certificate_store;

import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;

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
public interface CertificateDirectory {

    /**
     * Return the certificate that matches the given identifier.
     * If no matching certificate can be found, return null.
     *
     * @param identifier identifier for a certificate.
     * @return certificate or null
     *
     * @throws IOException in case of an IO-error
     */
    Certificate getCertificate(String identifier)
            throws IOException, BadNameException, BadDataException;

    /**
     * Return the certificate that matches the given identifier, but only iff it changed since the last invocation.
     * To compare the certificate against its last returned result, the given tag is used.
     * If the tag of the currently found certificate matches the given argument, return null.
     *
     * @param identifier identifier for a certificate
     * @param tag tag to compare freshness
     * @return changed certificate or null
     *
     * @throws IOException in case of an IO-error
     */
    Certificate getCertificateIfChanged(String identifier, String tag)
            throws IOException, BadNameException, BadDataException;

    /**
     * Insert a certificate into the store.
     * If an instance of the certificate is already present in the store, the given {@link MergeCallback} will be
     * used to merge both the existing and the new instance of the {@link Certificate}. The resulting merged certificate
     * will be stored in the store and returned.
     *
     * This method will block until a write-lock on the store can be acquired. If you cannot afford blocking,
     * consider to use {@link #tryInsertCertificate(InputStream, MergeCallback)} instead.
     *
     * @param data input stream containing the new certificate instance
     * @param merge callback for merging with an existing certificate instance
     * @return merged certificate
     *
     * @throws IOException in case of an IO-error
     * @throws InterruptedException in case the inserting thread gets interrupted
     */
    Certificate insertCertificate(InputStream data, MergeCallback merge)
            throws IOException, InterruptedException, BadDataException;

    /**
     * Insert a certificate into the store.
     * If an instance of the certificate is already present in the store, the given {@link MergeCallback} will be
     * used to merge both the existing and the new instance of the {@link Certificate}. The resulting merged certificate
     * will be stored in the store and returned.
     *
     * This method will not block. Instead, if the store is already write-locked, this method will simply return null
     * without any writing.
     * However, if the write-lock is available, this method will acquire the lock, write to the store, release the lock
     * and return the written certificate.
     *
     * @param data input stream containing the new certificate instance
     * @param merge callback for merging with an existing certificate instance
     * @return merged certificate or null if the store cannot be locked
     *
     * @throws IOException in case of an IO-error
     */
    Certificate tryInsertCertificate(InputStream data, MergeCallback merge)
            throws IOException, BadDataException;

    /**
     * Insert a certificate into the store.
     * The certificate will be stored under the given special name instead of its fingerprint.
     *
     * If an instance of the certificate is already present under the special name in the store, the given {@link MergeCallback} will be
     * used to merge both the existing and the new instance of the {@link Certificate}. The resulting merged certificate
     * will be stored in the store and returned.
     *
     * This method will block until a write-lock on the store can be acquired. If you cannot afford blocking,
     * consider to use {@link #tryInsertCertificateBySpecialName(String, InputStream, MergeCallback)}  instead.
     *
     * @param data input stream containing the new certificate instance
     * @param merge callback for merging with an existing certificate instance
     * @return merged certificate or null if the store cannot be locked
     *
     * @throws IOException in case of an IO-error
     */
    Certificate insertCertificateBySpecialName(String specialName, InputStream data, MergeCallback merge)
            throws IOException, InterruptedException, BadDataException, BadNameException;

    /**
     * Insert a certificate into the store.
     * The certificate will be stored under the given special name instead of its fingerprint.
     *
     * If an instance of the certificate is already present under the special name in the store, the given {@link MergeCallback} will be
     * used to merge both the existing and the new instance of the {@link Certificate}. The resulting merged certificate
     * will be stored in the store and returned.
     *
     * This method will not block. Instead, if the store is already write-locked, this method will simply return null
     * without any writing.
     * However, if the write-lock is available, this method will acquire the lock, write to the store, release the lock
     * and return the written certificate.
     *
     * @param data input stream containing the new certificate instance
     * @param merge callback for merging with an existing certificate instance
     * @return merged certificate or null if the store cannot be locked
     *
     * @throws IOException in case of an IO-error
     */
    Certificate tryInsertCertificateBySpecialName(String specialName, InputStream data, MergeCallback merge)
            throws IOException, BadDataException, BadNameException;

    /**
     * Return an {@link Iterator} containing all certificates in the store.
     * The iterator will contain both certificates addressed by special names and by fingerprints.
     *
     * @return certificates
     */
    Iterator<Certificate> getCertificates();

    /**
     * Return an {@link Iterator} containing all certificate fingerprints from the store.
     * Note that this only includes the fingerprints of certificate primary keys, not those of subkeys.
     *
     * @return fingerprints
     */
    Iterator<String> getFingerprints();
}
