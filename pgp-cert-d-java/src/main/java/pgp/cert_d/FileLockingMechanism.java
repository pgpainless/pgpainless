// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;

public class FileLockingMechanism implements LockingMechanism {

    private final File lockFile;
    private RandomAccessFile randomAccessFile;
    private FileLock fileLock;

    public FileLockingMechanism(File lockFile) {
        this.lockFile = lockFile;
    }

    public static FileLockingMechanism defaultDirectoryFileLock(File baseDirectory) {
        return new FileLockingMechanism(new File(baseDirectory, "writelock"));
    }

    @Override
    public synchronized void lockDirectory() throws IOException, InterruptedException {
        if (randomAccessFile != null) {
            // we own the lock already. Let's wait...
            this.wait();
        }

        try {
            randomAccessFile = new RandomAccessFile(lockFile, "rw");
        } catch (FileNotFoundException e) {
            lockFile.createNewFile();
            randomAccessFile = new RandomAccessFile(lockFile, "rw");
        }

        fileLock = randomAccessFile.getChannel().lock();
    }

    @Override
    public synchronized boolean tryLockDirectory() throws IOException {
        if (randomAccessFile != null) {
            // We already locked the directory for another write operation.
            // We fail, since we have not yet released the lock from the other operation.
            return false;
        }

        try {
            randomAccessFile = new RandomAccessFile(lockFile, "rw");
        } catch (FileNotFoundException e) {
            lockFile.createNewFile();
            randomAccessFile = new RandomAccessFile(lockFile, "rw");
        }

        try {
            fileLock = randomAccessFile.getChannel().tryLock();
            if (fileLock == null) {
                // try-lock failed, file is locked by another process.
                randomAccessFile.close();
                randomAccessFile = null;
                return false;
            }
        } catch (OverlappingFileLockException e) {
            // Some other object is holding the lock.
            randomAccessFile.close();
            randomAccessFile = null;
            return false;
        }
        return true;
    }

    @Override
    public synchronized void releaseDirectory() throws IOException {
        // unlock file
        if (fileLock != null) {
            fileLock.release();
            fileLock = null;
        }
        // close file
        if (randomAccessFile != null) {
            randomAccessFile.close();
            randomAccessFile = null;
        }
        // delete file
        if (lockFile.exists()) {
            lockFile.delete();
        }
        // notify waiters
        this.notify();
    }
}
