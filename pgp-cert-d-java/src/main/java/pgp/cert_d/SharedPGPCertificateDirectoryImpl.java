// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import pgp.certificate_store.exception.BadDataException;
import pgp.certificate_store.exception.BadNameException;
import pgp.certificate_store.exception.NotAStoreException;
import pgp.certificate_store.Certificate;
import pgp.certificate_store.CertificateReaderBackend;
import pgp.certificate_store.MergeCallback;

public class SharedPGPCertificateDirectoryImpl implements SharedPGPCertificateDirectory {

    private final FilenameResolver resolver;
    private final LockingMechanism writeLock;
    private final CertificateReaderBackend certificateReaderBackend;

    public SharedPGPCertificateDirectoryImpl(BackendProvider backendProvider)
            throws NotAStoreException {
        this(backendProvider.provideCertificateReaderBackend());
    }

    public SharedPGPCertificateDirectoryImpl(CertificateReaderBackend certificateReaderBackend)
            throws NotAStoreException {
        this(
                BaseDirectoryProvider.getDefaultBaseDir(),
                certificateReaderBackend);
    }

    public SharedPGPCertificateDirectoryImpl(File baseDirectory, CertificateReaderBackend certificateReaderBackend)
            throws NotAStoreException {
        this(
                certificateReaderBackend,
                new FilenameResolver(baseDirectory),
                FileLockingMechanism.defaultDirectoryFileLock(baseDirectory));
    }

    public SharedPGPCertificateDirectoryImpl(
            CertificateReaderBackend certificateReaderBackend,
            FilenameResolver filenameResolver,
            LockingMechanism writeLock)
            throws NotAStoreException {
        this.certificateReaderBackend = certificateReaderBackend;
        this.resolver = filenameResolver;
        this.writeLock = writeLock;

        File baseDirectory = resolver.getBaseDirectory();
        if (!baseDirectory.exists()) {
            if (!baseDirectory.mkdirs()) {
                throw new NotAStoreException("Cannot create base directory '" + resolver.getBaseDirectory().getAbsolutePath() + "'");
            }
        } else {
            if (baseDirectory.isFile()) {
                throw new NotAStoreException("Base directory '" + resolver.getBaseDirectory().getAbsolutePath() + "' appears to be a file.");
            }
        }
    }

    @Override
    public LockingMechanism getLock() {
        return writeLock;
    }

    @Override
    public Certificate getByFingerprint(String fingerprint)
            throws IOException, BadNameException, BadDataException {
        File certFile = resolver.getCertFileByFingerprint(fingerprint);
        if (!certFile.exists()) {
            return null;
        }

        FileInputStream fileIn = new FileInputStream(certFile);
        BufferedInputStream bufferedIn = new BufferedInputStream(fileIn);
        Certificate certificate = certificateReaderBackend.readCertificate(bufferedIn);

        if (!certificate.getFingerprint().equals(fingerprint)) {
            // TODO: Figure out more suitable exception
            throw new BadDataException();
        }

        return certificate;
    }

    @Override
    public Certificate getBySpecialName(String specialName)
            throws IOException, BadNameException {
        File certFile = resolver.getCertFileBySpecialName(specialName);
        if (!certFile.exists()) {
            return null;
        }

        FileInputStream fileIn = new FileInputStream(certFile);
        BufferedInputStream bufferedIn = new BufferedInputStream(fileIn);
        Certificate certificate = certificateReaderBackend.readCertificate(bufferedIn);

        return certificate;
    }

    @Override
    public Certificate getByFingerprintIfChanged(String fingerprint, String tag)
            throws IOException, BadNameException, BadDataException {
        Certificate certificate = getByFingerprint(fingerprint);
        if (certificate.getTag().equals(tag)) {
            return null;
        }
        return certificate;
    }

    @Override
    public Certificate getBySpecialNameIfChanged(String specialName, String tag)
            throws IOException, BadNameException {
        Certificate certificate = getBySpecialName(specialName);
        if (certificate.getTag().equals(tag)) {
            return null;
        }
        return certificate;
    }

    @Override
    public Certificate insert(InputStream data, MergeCallback merge)
            throws IOException, BadDataException, InterruptedException {
        writeLock.lockDirectory();

        Certificate certificate = _insert(data, merge);

        writeLock.releaseDirectory();
        return certificate;
    }

    @Override
    public Certificate tryInsert(InputStream data, MergeCallback merge)
            throws IOException, BadDataException {
        if (!writeLock.tryLockDirectory()) {
            return null;
        }

        Certificate certificate = _insert(data, merge);

        writeLock.releaseDirectory();
        return certificate;
    }

    private Certificate _insert(InputStream data, MergeCallback merge)
            throws IOException, BadDataException {
        Certificate newCertificate = certificateReaderBackend.readCertificate(data);
        Certificate existingCertificate;
        File certFile;
        try {
            existingCertificate = getByFingerprint(newCertificate.getFingerprint());
            certFile = resolver.getCertFileByFingerprint(newCertificate.getFingerprint());
        } catch (BadNameException e) {
            throw new BadDataException();
        }

        if (existingCertificate != null && !existingCertificate.getTag().equals(newCertificate.getTag())) {
            newCertificate = merge.merge(newCertificate, existingCertificate);
        }

        writeCertificate(newCertificate, certFile);

        return newCertificate;
    }

    private void writeCertificate(Certificate certificate, File certFile)
            throws IOException {
        certFile.getParentFile().mkdirs();
        if (!certFile.exists() && !certFile.createNewFile()) {
            throw new IOException("Could not create cert file " + certFile.getAbsolutePath());
        }

        InputStream certIn = certificate.getInputStream();
        FileOutputStream fileOut = new FileOutputStream(certFile);

        byte[] buffer = new byte[4096];
        int read;
        while ((read = certIn.read(buffer)) != -1) {
            fileOut.write(buffer, 0, read);
        }

        certIn.close();
        fileOut.close();
    }

    @Override
    public Certificate insertWithSpecialName(String specialName, InputStream data, MergeCallback merge)
            throws IOException, BadNameException, BadDataException, InterruptedException {
        writeLock.lockDirectory();

        Certificate certificate = _insertSpecial(specialName, data, merge);

        writeLock.releaseDirectory();
        return certificate;
    }

    @Override
    public Certificate tryInsertWithSpecialName(String specialName, InputStream data, MergeCallback merge)
            throws IOException, BadNameException, BadDataException {
        if (!writeLock.tryLockDirectory()) {
            return null;
        }

        Certificate certificate = _insertSpecial(specialName, data, merge);

        writeLock.releaseDirectory();
        return certificate;
    }

    private Certificate _insertSpecial(String specialName, InputStream data, MergeCallback merge)
            throws IOException, BadNameException, BadDataException {
        Certificate newCertificate = certificateReaderBackend.readCertificate(data);
        Certificate existingCertificate = getBySpecialName(specialName);
        File certFile = resolver.getCertFileBySpecialName(specialName);

        if (existingCertificate != null && !existingCertificate.getTag().equals(newCertificate.getTag())) {
            newCertificate = merge.merge(newCertificate, existingCertificate);
        }

        writeCertificate(newCertificate, certFile);

        return newCertificate;
    }

    @Override
    public Iterator<Certificate> items() {
        return new Iterator<Certificate>() {

            private final List<Lazy<Certificate>> certificateQueue = Collections.synchronizedList(new ArrayList<>());

            // Constructor... wtf.
            {
                File[] subdirectories = resolver.getBaseDirectory().listFiles(new FileFilter() {
                            @Override
                            public boolean accept(File file) {
                                return file.isDirectory() && file.getName().matches("^[a-f0-9]{2}$");
                            }
                        });

                for (File subdirectory : subdirectories) {
                    File[] files = subdirectory.listFiles(new FileFilter() {
                        @Override
                        public boolean accept(File file) {
                            return file.isFile() && file.getName().matches("^[a-f0-9]{38}$");
                        }
                    });

                    for (File certFile : files) {
                        certificateQueue.add(new Lazy<Certificate>() {
                            @Override
                            Certificate get() throws BadDataException {
                                try {
                                    Certificate certificate = certificateReaderBackend.readCertificate(new FileInputStream(certFile));
                                    if (!(subdirectory.getName() + certFile.getName()).equals(certificate.getFingerprint())) {
                                        throw new BadDataException();
                                    }
                                    return certificate;
                                } catch (IOException e) {
                                    throw new AssertionError("File got deleted.");
                                }
                            }
                        });
                    }
                }
            }

            @Override
            public boolean hasNext() {
                return !certificateQueue.isEmpty();
            }

            @Override
            public Certificate next() {
                try {
                    return certificateQueue.remove(0).get();
                } catch (BadDataException e) {
                    throw new AssertionError("Could not retrieve item: " + e.getMessage());
                }
            }
        };
    }

    private abstract static class Lazy<E> {
        abstract E get() throws BadDataException;
    }

    @Override
    public Iterator<String> fingerprints() {
        Iterator<Certificate> certificates = items();
        return new Iterator<String>() {
            @Override
            public boolean hasNext() {
                return certificates.hasNext();
            }

            @Override
            public String next() {
                return certificates.next().getFingerprint();
            }
        };
    }
}
