package pgp.cert_d;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.util.Iterator;
import java.util.regex.Pattern;

import pgp.cert_d.exception.BadDataException;
import pgp.cert_d.exception.BadNameException;
import pgp.cert_d.exception.NotAStoreException;
import pgp.certificate_store.Item;
import pgp.certificate_store.MergeCallback;

public class SharedPGPCertificateDirectoryImpl implements SharedPGPCertificateDirectory {

    private final File baseDirectory;
    private final Pattern openPgpV4FingerprintPattern = Pattern.compile("^[a-f0-9]{40}$");

    private final WriteLock writeLock;

    public SharedPGPCertificateDirectoryImpl() throws NotAStoreException {
        this(OSUtil.getDefaultBaseDir());
    }

    public SharedPGPCertificateDirectoryImpl(File baseDirectory) throws NotAStoreException {
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
        writeLock = new WriteLock(new File(getBaseDirectory(), "writelock"));
    }

    public File getBaseDirectory() {
        return baseDirectory;
    }

    private File getCertFile(String identifier) throws BadNameException {
        SpecialName specialName = SpecialName.fromString(identifier);
        if (specialName != null) {
            // is special name
            return new File(getBaseDirectory(), specialName.getValue());
        } else {
            if (!isFingerprint(identifier)) {
                throw new BadNameException();
            }

            // is fingerprint
            File subdirectory = new File(getBaseDirectory(), identifier.substring(0, 2));
            File file = new File(subdirectory, identifier.substring(2));
            return file;
        }
    }

    private boolean isFingerprint(String identifier) {
        return openPgpV4FingerprintPattern.matcher(identifier).matches();
    }

    @Override
    public Item get(String identifier) throws IOException, BadNameException {
        File certFile = getCertFile(identifier);
        if (certFile.exists()) {
            return new Item(identifier, "TAG", new FileInputStream(certFile));
        }
        return null;
    }

    @Override
    public Item getIfChanged(String identifier, String tag) throws IOException, BadNameException {
        return null;
    }

    @Override
    public Item insert(InputStream data, MergeCallback merge) throws IOException, BadDataException {
        writeLock.lock();

        Item item = _insert(data, merge);

        writeLock.release();
        return item;
    }

    @Override
    public Item tryInsert(InputStream data, MergeCallback merge) throws IOException, BadDataException {
        if (!writeLock.tryLock()) {
            return null;
        }

        Item item = _insert(data, merge);

        writeLock.release();
        return item;
    }

    private Item _insert(InputStream data, MergeCallback merge) throws IOException, BadDataException {
        return null;
    }

    @Override
    public Item insertSpecial(String specialName, InputStream data, MergeCallback merge) throws IOException, BadNameException, BadDataException {
        writeLock.lock();

        Item item = _insertSpecial(specialName, data, merge);

        writeLock.release();
        return item;
    }

    @Override
    public Item tryInsertSpecial(String specialName, InputStream data, MergeCallback merge) throws IOException, BadNameException, BadDataException {
        if (!writeLock.tryLock()) {
            return null;
        }

        Item item = _insertSpecial(specialName, data, merge);

        writeLock.release();
        return item;
    }

    private Item _insertSpecial(String specialName, InputStream data, MergeCallback merge) throws IOException, BadNameException, BadDataException {
        return null;
    }

    @Override
    public Iterator<Item> items() {
        return null;
    }

    @Override
    public Iterator<String> fingerprints() {
        return null;
    }

    public static class WriteLock {
        private final File lockFile;
        private RandomAccessFile randomAccessFile;
        private FileLock fileLock;

        public WriteLock(File lockFile) {
            this.lockFile = lockFile;
        }

        public synchronized void lock() throws IOException {
            if (randomAccessFile != null) {
                throw new IllegalStateException("File already locked.");
            }

            try {
                randomAccessFile = new RandomAccessFile(lockFile, "rw");
            } catch (FileNotFoundException e) {
                lockFile.createNewFile();
                randomAccessFile = new RandomAccessFile(lockFile, "rw");
            }

            fileLock = randomAccessFile.getChannel().lock();
        }

        public synchronized boolean tryLock() throws IOException {
            if (randomAccessFile != null) {
                return false;
            }

            try {
                randomAccessFile = new RandomAccessFile(lockFile, "rw");
            } catch (FileNotFoundException e) {
                lockFile.createNewFile();
                randomAccessFile = new RandomAccessFile(lockFile, "rw");
            }

            fileLock = randomAccessFile.getChannel().tryLock();
            if (fileLock == null) {
                randomAccessFile.close();
                randomAccessFile = null;
                return false;
            }
            return true;
        }

        public synchronized void release() throws IOException {
            if (lockFile.exists()) {
                lockFile.delete();
            }
            if (fileLock != null) {
                fileLock.release();
                fileLock = null;
            }
            if (randomAccessFile != null) {
                randomAccessFile.close();
                randomAccessFile = null;
            }
        }
    }
}
