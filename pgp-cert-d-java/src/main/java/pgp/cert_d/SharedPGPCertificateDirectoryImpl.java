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
import java.util.Iterator;
import java.util.Queue;
import java.util.concurrent.SynchronousQueue;
import java.util.regex.Pattern;

import pgp.cert_d.exception.BadDataException;
import pgp.cert_d.exception.BadNameException;
import pgp.cert_d.exception.NotAStoreException;
import pgp.certificate_store.Certificate;
import pgp.certificate_store.MergeCallback;
import pgp.certificate_store.ParserBackend;

public class SharedPGPCertificateDirectoryImpl implements SharedPGPCertificateDirectory {

    private final File baseDirectory;
    private final Pattern openPgpV4FingerprintPattern = Pattern.compile("^[a-f0-9]{40}$");

    private final LockingMechanism writeLock;
    private final ParserBackend parserBackend;

    public SharedPGPCertificateDirectoryImpl(ParserBackend parserBackend)
            throws NotAStoreException {
        this(OSUtil.getDefaultBaseDir(), parserBackend);
    }

    public SharedPGPCertificateDirectoryImpl(File baseDirectory, ParserBackend parserBackend)
            throws NotAStoreException {
        this.parserBackend = parserBackend;
        this.baseDirectory = baseDirectory;
        if (!baseDirectory.exists()) {
            if (!baseDirectory.mkdirs()) {
                throw new NotAStoreException("Cannot create base directory '" + getBaseDirectory().getAbsolutePath() + "'");
            }
        } else {
            if (baseDirectory.isFile()) {
                throw new NotAStoreException("Base directory '" + getBaseDirectory().getAbsolutePath() + "' appears to be a file.");
            }
        }
        writeLock = new FileLockingMechanism(new File(getBaseDirectory(), "writelock"));
    }

    public File getBaseDirectory() {
        return baseDirectory;
    }

    private File getCertFile(String fingerprint) throws BadNameException {
        if (!isFingerprint(fingerprint)) {
            throw new BadNameException();
        }

        // is fingerprint
        File subdirectory = new File(getBaseDirectory(), fingerprint.substring(0, 2));
        File file = new File(subdirectory, fingerprint.substring(2));
        return file;
    }

    private File getCertFile(SpecialName specialName) {
        return new File(getBaseDirectory(), specialName.getValue());
    }

    private boolean isFingerprint(String fingerprint) {
        return openPgpV4FingerprintPattern.matcher(fingerprint).matches();
    }

    @Override
    public Certificate get(String fingerprint) throws IOException, BadNameException {
        File certFile = getCertFile(fingerprint);
        if (!certFile.exists()) {
            return null;
        }
        FileInputStream fileIn = new FileInputStream(certFile);
        BufferedInputStream bufferedIn = new BufferedInputStream(fileIn);
        Certificate certificate = parserBackend.readCertificate(bufferedIn);

        if (!certificate.getFingerprint().equals(fingerprint)) {
            // TODO: Figure out more suitable exception
            throw new BadNameException();
        }

        return certificate;
    }

    @Override
    public Certificate get(SpecialName specialName) throws IOException {
        File certFile = getCertFile(specialName);
        if (!certFile.exists()) {
            return null;
        }

        FileInputStream fileIn = new FileInputStream(certFile);
        BufferedInputStream bufferedIn = new BufferedInputStream(fileIn);
        Certificate certificate = parserBackend.readCertificate(bufferedIn);

        return certificate;
    }

    @Override
    public Certificate getIfChanged(String fingerprint, String tag) throws IOException, BadNameException {
        Certificate certificate = get(fingerprint);
        if (certificate.getTag().equals(tag)) {
            return null;
        }
        return certificate;
    }

    @Override
    public Certificate getIfChanged(SpecialName specialName, String tag) throws IOException {
        Certificate certificate = get(specialName);
        if (certificate.getTag().equals(tag)) {
            return null;
        }
        return certificate;
    }

    @Override
    public Certificate insert(InputStream data, MergeCallback merge) throws IOException, BadDataException, InterruptedException {
        writeLock.lockDirectory();

        Certificate certificate = _insert(data, merge);

        writeLock.releaseDirectory();
        return certificate;
    }

    @Override
    public Certificate tryInsert(InputStream data, MergeCallback merge) throws IOException, BadDataException {
        if (!writeLock.tryLockDirectory()) {
            return null;
        }

        Certificate certificate = _insert(data, merge);

        writeLock.releaseDirectory();
        return certificate;
    }

    private Certificate _insert(InputStream data, MergeCallback merge) throws IOException, BadDataException {
        Certificate newCertificate = parserBackend.readCertificate(data);
        Certificate existingCertificate;
        File certFile;
        try {
            existingCertificate = get(newCertificate.getFingerprint());
            certFile = getCertFile(newCertificate.getFingerprint());
        } catch (BadNameException e) {
            throw new BadDataException();
        }

        if (existingCertificate != null && !existingCertificate.getTag().equals(newCertificate.getTag())) {
            newCertificate = merge.merge(newCertificate, existingCertificate);
        }

        writeCertificate(newCertificate, certFile);

        return newCertificate;
    }

    private void writeCertificate(Certificate certificate, File certFile) throws IOException {
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
    public Certificate insertSpecial(SpecialName specialName, InputStream data, MergeCallback merge) throws IOException, BadNameException, BadDataException, InterruptedException {
        writeLock.lockDirectory();

        Certificate certificate = _insertSpecial(specialName, data, merge);

        writeLock.releaseDirectory();
        return certificate;
    }

    @Override
    public Certificate tryInsertSpecial(SpecialName specialName, InputStream data, MergeCallback merge) throws IOException, BadNameException, BadDataException {
        if (!writeLock.tryLockDirectory()) {
            return null;
        }

        Certificate certificate = _insertSpecial(specialName, data, merge);

        writeLock.releaseDirectory();
        return certificate;
    }

    private Certificate _insertSpecial(SpecialName specialName, InputStream data, MergeCallback merge) throws IOException, BadNameException, BadDataException {
        Certificate newCertificate = parserBackend.readCertificate(data);
        Certificate existingCertificate = get(specialName);
        File certFile = getCertFile(specialName);

        if (existingCertificate != null && !existingCertificate.getTag().equals(newCertificate.getTag())) {
            newCertificate = merge.merge(newCertificate, existingCertificate);
        }

        writeCertificate(newCertificate, certFile);

        return newCertificate;
    }

    @Override
    public Iterator<Certificate> items() {
        return new Iterator<Certificate>() {

            private final Queue<Lazy<Certificate>> certificateQueue = new SynchronousQueue<>();

            // Constructor... wtf.
            {
                for (SpecialName specialName : SpecialName.values()) {
                    File certFile = getCertFile(specialName);
                    if (certFile.exists()) {
                        certificateQueue.add(
                                new Lazy<Certificate>() {
                                    @Override
                                    Certificate get() {
                                        try {
                                            return parserBackend.readCertificate(new FileInputStream(certFile));
                                        } catch (IOException e) {
                                            throw new AssertionError("File got deleted.");
                                        }
                                    }
                                });
                    }
                }

                File[] subdirectories = baseDirectory.listFiles(new FileFilter() {
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
                                    Certificate certificate = parserBackend.readCertificate(new FileInputStream(certFile));
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
                    return certificateQueue.poll().get();
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
