// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d;

import java.io.IOException;

public interface LockingMechanism {

    /**
     * Lock the store for writes.
     * Readers can continue to use the store and will always see consistent certs.
     */
    void lockDirectory() throws IOException, InterruptedException;

    /**
     * Try top lock the store for writes.
     * Return false without locking the store in case the store was already locked.
     *
     * @return true if locking succeeded, false otherwise
     */
    boolean tryLockDirectory() throws IOException;

    /**
     * Release the directory write-lock acquired via {@link #lockDirectory()}.
     */
    void releaseDirectory() throws IOException;

}
